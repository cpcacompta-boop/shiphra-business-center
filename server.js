// ============================================================
//  Shiphra Business Center — Serveur (Express + PostgreSQL)
//  Sert l'application, enregistre toutes les données en base,
//  et gère maintenant les comptes (Superviseure + Agents).
// ============================================================

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '5mb' }));           // accepte les grosses sauvegardes JSON
app.use(express.static(path.join(__dirname, 'public'))); // sert public/index.html

// --- Connexion à la base PostgreSQL de Render ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- Mot de passe par défaut donné à tout nouveau compte ---
const DEFAULT_PASSWORD = '0000';

// --- Sessions en mémoire (token -> { username, role, nomComplet }) ---
// Simple et suffisant pour la taille de l'équipe. Redémarre = tout le monde
// doit se reconnecter (ça arrive rarement sur Render).
const sessions = new Map();

// ---------- Utilitaires mot de passe (hash + sel, sans dépendance externe) ----------
function hashPassword(password, salt) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), usedSalt, 64).toString('hex');
  return { hash, salt: usedSalt };
}
function verifyPassword(password, hash, salt) {
  const attempt = crypto.scryptSync(String(password), salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(hash, 'hex'));
  } catch (e) {
    return false;
  }
}
function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}
function normalizeUsername(u) {
  return String(u || '').trim().toLowerCase();
}

// ---------- Création automatique des tables au démarrage ----------
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_store (
      k TEXT PRIMARY KEY,
      v JSONB NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      nom_complet TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('superviseur','agent')),
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  // Si aucun compte n'existe encore, on crée le compte Superviseure de départ.
  const r = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  if (r.rows[0].n === 0) {
    const { hash, salt } = hashPassword(DEFAULT_PASSWORD);
    await pool.query(
      `INSERT INTO users (username, nom_complet, role, password_hash, password_salt, must_change_password, active)
       VALUES ($1,$2,$3,$4,$5,TRUE,TRUE)`,
      ['patronne', 'Superviseure', 'superviseur', hash, salt]
    );
    console.log('Compte Superviseure créé par défaut -> identifiant: patronne / mot de passe: 0000 (à changer à la 1ère connexion).');
  }

  console.log('Tables prêtes (app_store, users).');
}

// ---------- Middleware d'authentification ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const session = token ? sessions.get(token) : null;
  if (!session) return res.status(401).json({ error: 'Non authentifié' });
  req.session = session;
  next();
}
function requireSuperviseur(req, res, next) {
  if (req.session.role !== 'superviseur') {
    return res.status(403).json({ error: 'Réservé à la Superviseure' });
  }
  next();
}

// =========================================================
//  AUTHENTIFICATION
// =========================================================

// --- Connexion ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });

    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });

    const user = r.rows[0];
    if (!user.active) return res.status(403).json({ error: 'Ce compte a été désactivé. Contacte la Superviseure.' });

    const ok = verifyPassword(password, user.password_hash, user.password_salt);
    if (!ok) return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });

    const token = makeToken();
    sessions.set(token, { username: user.username, role: user.role, nomComplet: user.nom_complet });

    res.json({
      ok: true,
      token,
      username: user.username,
      role: user.role,
      nomComplet: user.nom_complet,
      mustChangePassword: user.must_change_password
    });
  } catch (e) {
    console.error('Erreur login:', e);
    res.status(500).json({ error: 'Erreur de connexion au serveur.' });
  }
});

// --- Changement de mot de passe (1ère connexion obligatoire, ou volontaire) ---
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!newPassword || String(newPassword).length < 4) {
      return res.status(400).json({ error: 'Le nouveau mot de passe doit contenir au moins 4 caractères.' });
    }
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [req.session.username]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Compte introuvable.' });
    const user = r.rows[0];

    const ok = verifyPassword(String(oldPassword || ''), user.password_hash, user.password_salt);
    if (!ok) return res.status(401).json({ error: 'Mot de passe actuel incorrect.' });

    const { hash, salt } = hashPassword(newPassword);
    await pool.query(
      'UPDATE users SET password_hash=$1, password_salt=$2, must_change_password=FALSE WHERE username=$3',
      [hash, salt, user.username]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur changement mdp:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- Vérifier la session actuelle (utilisé au chargement de l'app) ---
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, ...req.session });
});

// --- Déconnexion ---
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.slice(7);
  sessions.delete(token);
  res.json({ ok: true });
});

// =========================================================
//  GESTION DES COMPTES (réservé à la Superviseure)
// =========================================================

app.get('/api/users', requireAuth, requireSuperviseur, async (req, res) => {
  const r = await pool.query(
    'SELECT username, nom_complet, role, active, must_change_password, created_at FROM users ORDER BY created_at ASC'
  );
  res.json(r.rows.map(u => ({
    username: u.username,
    nomComplet: u.nom_complet,
    role: u.role,
    active: u.active,
    mustChangePassword: u.must_change_password,
    createdAt: u.created_at
  })));
});

app.post('/api/users', requireAuth, requireSuperviseur, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const nomComplet = String(req.body.nomComplet || '').trim();
    const role = req.body.role === 'superviseur' ? 'superviseur' : 'agent';

    if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
      return res.status(400).json({ error: "Identifiant invalide (3 à 30 caractères : lettres, chiffres, '.', '_', '-')." });
    }
    if (!nomComplet) return res.status(400).json({ error: 'Le nom complet est requis.' });

    const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
    if (exists.rows.length > 0) return res.status(409).json({ error: 'Cet identifiant existe déjà.' });

    const { hash, salt } = hashPassword(DEFAULT_PASSWORD);
    await pool.query(
      `INSERT INTO users (username, nom_complet, role, password_hash, password_salt, must_change_password, active)
       VALUES ($1,$2,$3,$4,$5,TRUE,TRUE)`,
      [username, nomComplet, role, hash, salt]
    );
    res.json({ ok: true, username, nomComplet, role, defaultPassword: DEFAULT_PASSWORD });
  } catch (e) {
    console.error('Erreur création compte:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.patch('/api/users/:username', requireAuth, requireSuperviseur, async (req, res) => {
  try {
    const username = normalizeUsername(req.params.username);
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Compte introuvable.' });
    const user = r.rows[0];

    if (typeof req.body.active === 'boolean') {
      if (user.username === req.session.username && req.body.active === false) {
        return res.status(400).json({ error: 'Tu ne peux pas désactiver ton propre compte.' });
      }
      await pool.query('UPDATE users SET active=$1 WHERE username=$2', [req.body.active, username]);
    }
    if (req.body.role === 'agent' || req.body.role === 'superviseur') {
      await pool.query('UPDATE users SET role=$1 WHERE username=$2', [req.body.role, username]);
    }
    if (req.body.nomComplet) {
      await pool.query('UPDATE users SET nom_complet=$1 WHERE username=$2', [String(req.body.nomComplet).trim(), username]);
    }
    if (req.body.resetPassword === true) {
      const { hash, salt } = hashPassword(DEFAULT_PASSWORD);
      await pool.query(
        'UPDATE users SET password_hash=$1, password_salt=$2, must_change_password=TRUE WHERE username=$3',
        [hash, salt, username]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur mise à jour compte:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.delete('/api/users/:username', requireAuth, requireSuperviseur, async (req, res) => {
  try {
    const username = normalizeUsername(req.params.username);
    if (username === req.session.username) {
      return res.status(400).json({ error: 'Tu ne peux pas supprimer ton propre compte.' });
    }
    await pool.query('DELETE FROM users WHERE username=$1', [username]);
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur suppression compte:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// =========================================================
//  DONNÉES DE L'APPLICATION (ventes, stock, dépenses...)
// =========================================================

app.get('/api/data', async (req, res) => {
  try {
    const r = await pool.query('SELECT v FROM app_store WHERE k = $1', ['app-data']);
    if (r.rows.length === 0) return res.json(null); // aucune donnée encore
    res.json(r.rows[0].v);
  } catch (e) {
    console.error('Erreur lecture:', e);
    res.status(500).json({ error: 'lecture impossible' });
  }
});

app.post('/api/data', async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO app_store (k, v) VALUES ($1, $2)
       ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`,
      ['app-data', req.body]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur écriture:', e);
    res.status(500).json({ error: 'sauvegarde impossible' });
  }
});

// --- Démarrage ---
const PORT = process.env.PORT || 3000;
init()
  .then(() => app.listen(PORT, () => console.log('Serveur démarré sur le port ' + PORT)))
  .catch(e => { console.error('Échec démarrage:', e); process.exit(1); });