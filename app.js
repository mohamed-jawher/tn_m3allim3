const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const app = express();

// Connexion à la base de données MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'tn_m3allim'
});

db.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à la base de données:', err.stack);
        return;
    }
    console.log('Connecté à la base de données MySQL');
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Route principale
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Inscription d'un utilisateur
app.post('/signup', (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.json({ success: false, message: 'Toutes les informations sont requises' });
    }

    // Vérifier si l'utilisateur existe déjà
    db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Erreur lors de la vérification de l\'email:', err);
            return res.status(500).json({ success: false, message: 'Erreur serveur' });
        }

        if (results.length > 0) {
            return res.json({ success: false, message: 'Cet utilisateur existe déjà !' });
        }

        // Hachage du mot de passe
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Erreur de hachage:', err);
                return res.status(500).json({ success: false, message: 'Erreur serveur' });
            }

            // Insertion dans la base de données
            const query = 'INSERT INTO utilisateurs (nom, email, mot_de_passe, rôle) VALUES (?, ?, ?, ?)';
            db.query(query, [name, email, hashedPassword, role], (err) => {
                if (err) {
                    console.error('Erreur lors de l\'ajout de l\'utilisateur:', err);
                    return res.status(500).json({ success: false, message: 'Erreur serveur' });
                }

                res.json({ success: true, message: 'Utilisateur ajouté avec succès' });
            });
        });
    });
});

// Connexion d'un utilisateur
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Erreur lors de la récupération de l\'utilisateur:', err);
            return res.status(500).json({ success: false, message: 'Erreur serveur' });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: 'Utilisateur non trouvé' });
        }

        const user = results[0];

        // Comparaison du mot de passe
        bcrypt.compare(password, user.mot_de_passe, (err, isMatch) => {
            if (err) {
                console.error('Erreur lors de la comparaison:', err);
                return res.status(500).json({ success: false, message: 'Erreur serveur' });
            }

            if (!isMatch) {
                return res.json({ success: false, message: 'Mot de passe incorrect' });
            }

            // Redirection selon le rôle
            let redirectPage = '';
            if (user.rôle === 'admin') {
                redirectPage = 'admin.html';
            } else if (user.rôle === 'artisan') {
                redirectPage = 'artisan.html';
            } else if (user.rôle === 'client') {
                redirectPage = 'client.html';
            } else {
                return res.json({ success: false, message: 'Rôle non autorisé' });
            }

            res.json({ success: true, redirect: redirectPage });
        });
    });
});







// Définition du port
const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Serveur démarré sur http://localhost:${port}`);
});
