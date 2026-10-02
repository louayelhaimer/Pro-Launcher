const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./users.db');

// --- MIDDLEWARES ---
// Permet de lire les données JSON envoyées par le JS frontend
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sert les fichiers statiques (html, css, images, exe) depuis le dossier public
app.use(express.static(path.join(__dirname, 'public')));

// Configuration des sessions
app.use(session({
    secret: 'mon_secret_super_securise_123',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // La session dure 24h
}));

// --- INITIALISATION DE LA BASE DE DONNÉES ---
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
)`);

// --- ROUTES API AUTHENTIFICATION ---

// 1. INSCRIPTION (Register)
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Tous les champs sont obligatoires.' });
    }

    try {
        // Hachage sécurisé du mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertion dans SQLite
        db.run(
            `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Ce pseudo ou cet email est déjà utilisé.' });
                    }
                    return res.status(500).json({ error: 'Erreur lors de l\'enregistrement.' });
                }

                // Connecte l'utilisateur immédiatement après l'inscription
                req.session.user = { id: this.lastID, username };
                res.json({ success: true, username });
            }
        );
    } catch (e) {
        res.status(500).json({ error: 'Erreur serveur lors du chiffrement.' });
    }
});

// 2. CONNEXION (Login)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Veuillez remplir tous les champs.' });
    }

    // Recherche de l'utilisateur par son pseudo
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Nom d\'utilisateur ou mot de passe incorrect.' });
        }

        // Vérification du mot de passe
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Nom d\'utilisateur ou mot de passe incorrect.' });
        }

        // Création de la session
        req.session.user = { id: user.id, username: user.username };
        res.json({ success: true, username: user.username });
    });
});

// 3. OBTENIR L'UTILISATEUR CONNECTÉ (Session active)
app.get('/api/me', (req, res) => {
    if (req.session && req.session.user) {
        res.json({ loggedIn: true, username: req.session.user.username });
    } else {
        res.json({ loggedIn: false });
    }
});

// 4. DÉCONNEXION (Logout)
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur lors de la déconnexion.' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// --- DÉMARRAGE DU SERVEUR ---
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Serveur démarré avec succès sur http://localhost:${PORT}`);
});