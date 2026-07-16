// ============================================================
//  Shiphra Business Center — Serveur (Express + PostgreSQL)
//  v6 — Multi-localités
//  Rôles : Gérant (admin, main sur tout) · Superviseur (consulte)
//          · Vente (vend dans SA localité).
//  Le Gérant crée et gère lui-même les localités.
// ============================================================

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '5mb' }));
// --- Routage des pages (comme les applis pro : la CONNEXION d'abord) ---
// index:false = on empêche Express de servir index.html tout seul sur "/".
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// L'adresse principale montre TOUJOURS la page de connexion.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
// L'application elle-même vit sur /app (sans session, elle renvoie aussitôt
// vers la page de connexion).
app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  // Réglages de robustesse (comme les applis pro) :
  max: 10,                      // pas plus de 10 connexions à la fois
  idleTimeoutMillis: 30000,     // libère les connexions inutilisées
  connectionTimeoutMillis: 10000, // n'attend pas indéfiniment
  keepAlive: true               // évite que le réseau coupe la connexion
});

// Si une connexion inactive tombe, on ne veut PAS que le serveur plante.
pool.on('error', (err) => {
  console.error('Connexion base perdue (le serveur continue et se reconnectera) :', err.message);
});

// Mot de passe temporaire donné à tout nouveau compte
const DEFAULT_PASSWORD = '0000';

// Sessions en mémoire (token -> { username, role, nomComplet, localiteId })
const sessions = new Map();

// Une session est considérée VIVANTE si elle a donné signe de vie récemment.
// (L'application envoie un signal toutes les 5 secondes via /api/sync.)
const DELAI_SESSION_VIVANTE_MS = 30 * 1000; // 30 secondes
function sessionVivante(username){
  const maintenant = Date.now();
  for(const [tok, s] of sessions){
    if(s.username === username && (maintenant - (s.lastSeen || 0)) < DELAI_SESSION_VIVANTE_MS){
      return { token: tok, session: s };
    }
  }
  return null;
}

// Quand une session est coupée (compte désactivé, ou connexion depuis un autre
// appareil), on garde la RAISON un moment pour l'expliquer clairement à la
// personne au lieu d'un simple "non authentifié".
const raisonsRevocation = new Map(); // token -> { raison, at }

function revoquerToken(token, raison){
  sessions.delete(token);
  raisonsRevocation.set(token, { raison, at: Date.now() });
  // On ne garde pas les raisons éternellement (nettoyage au-delà de 30 min)
  if (raisonsRevocation.size > 500) {
    const limite = Date.now() - 30 * 60 * 1000;
    for (const [t, v] of raisonsRevocation) { if (v.at < limite) raisonsRevocation.delete(t); }
  }
}

// Déconnecte immédiatement toutes les sessions ouvertes d'un utilisateur
// (utilisé quand on le désactive/supprime, ou qu'il se connecte ailleurs).
function purgeUserSessions(username, raison, saufToken){
  for(const [tok, s] of sessions){
    if(s.username === username && tok !== saufToken){
      revoquerToken(tok, raison || 'Session terminée.');
    }
  }
}

// ---------- Utilitaires mot de passe ----------
function hashPassword(password, salt) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), usedSalt, 64).toString('hex');
  return { hash, salt: usedSalt };
}
function verifyPassword(password, hash, salt) {
  const attempt = crypto.scryptSync(String(password), salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(hash, 'hex'));
  } catch (e) { return false; }
}
function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function makeId()    { return crypto.randomBytes(9).toString('hex'); }
function normalizeUsername(u) { return String(u || '').trim().toLowerCase(); }

const ROLES = ['gerant', 'superviseur', 'vente', 'caisse'];
function normalizeRole(r) {
  if (r === 'agent') return 'vente';            // ancien rôle -> nouveau
  return ROLES.includes(r) ? r : 'vente';
}

// --- Gestion des sessions en direct (pour appliquer les actions immédiatement) ---
// Coupe TOUTES les sessions ouvertes d'un utilisateur : à sa prochaine requête il
// sera renvoyé vers la connexion (utile quand on le désactive / supprime / reset).
function killUserSessions(username) {
  for (const [token, s] of sessions) {
    if (s.username === username) sessions.delete(token);
  }
}
// Met à jour à chaud les infos d'une session ouverte (rôle, nom, localité) sans
// déconnecter la personne — ses droits changent en direct.
function patchUserSessions(username, patch) {
  for (const [, s] of sessions) {
    if (s.username === username) Object.assign(s, patch);
  }
}

// ---------- Création / mise à jour des tables au démarrage ----------
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_store (
      k TEXT PRIMARY KEY,
      v JSONB NOT NULL
    )
  `);
  // Horodatage de la dernière modification des données (sert au temps réel :
  // les autres appareils détectent qu'il y a du nouveau et se rafraîchissent).
  await pool.query(`ALTER TABLE app_store ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS localites (
      id TEXT PRIMARY KEY,
      nom TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      nom_complet TEXT NOT NULL,
      role TEXT NOT NULL,
      localite_id TEXT,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  // --- Migration douce d'une ancienne base (rôles superviseur/agent) ---
  // Tout est protégé : si une étape échoue sur une base particulière, on continue
  // quand même, l'application valide déjà les rôles côté serveur.
  try {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS localite_id TEXT`);
  } catch (e) { console.warn('Migration localite_id ignorée:', e.message); }
  try {
    await pool.query(`UPDATE users SET role='vente' WHERE role='agent'`);
  } catch (e) { console.warn('Migration rôle agent ignorée:', e.message); }
  try {
    // On retire l'ancienne contrainte de rôle (superviseur/agent) si elle existe,
    // pour ne pas bloquer les nouveaux rôles. Pas de nouvelle contrainte SQL :
    // la validation se fait proprement dans le code (fonction normalizeRole).
    await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check`);
  } catch (e) { console.warn('Nettoyage contrainte rôle ignoré:', e.message); }

  // --- Le compte principal "shiphra" existe TOUJOURS comme GÉRANT (main sur tout) ---
  const existing = await pool.query('SELECT username FROM users WHERE username = $1', ['shiphra']);
  const { hash, salt } = hashPassword('Shiphra@12345');
  if (existing.rows.length === 0) {
    await pool.query(
      `INSERT INTO users (username, nom_complet, role, password_hash, password_salt, must_change_password, active)
       VALUES ($1,$2,$3,$4,$5,FALSE,TRUE)`,
      ['shiphra', 'Gérant', 'gerant', hash, salt]
    );
    console.log('Compte Gérant créé -> identifiant: shiphra.');
  } else {
    await pool.query(
      `UPDATE users SET password_hash=$1, password_salt=$2, role='gerant', active=TRUE, must_change_password=FALSE WHERE username='shiphra'`,
      [hash, salt]
    );
    console.log('Compte Gérant "shiphra" vérifié / resynchronisé.');
  }

  console.log('Tables prêtes (app_store, users, localites).');
}

// ---------- Middlewares d'authentification ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const session = token ? sessions.get(token) : null;
  if (!session) {
    const rev = token ? raisonsRevocation.get(token) : null;
    return res.status(401).json({
      error: rev ? rev.raison : 'Non authentifié',
      raison: rev ? rev.raison : null
    });
  }
  req.session = session;
  next();
}
function requireGerant(req, res, next) {
  if (req.session.role !== 'gerant') {
    return res.status(403).json({ error: 'Réservé au Gérant' });
  }
  next();
}

// =========================================================
//  AUTHENTIFICATION
// =========================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });

    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });

    const user = r.rows[0];
    if (!user.active) return res.status(403).json({ error: 'Ce compte a été désactivé. Contacte le Gérant.' });

    const ok = verifyPassword(password, user.password_hash, user.password_salt);
    if (!ok) return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });

    // SÉCURITÉ : un compte = un seul appareil. Si ce compte est DÉJÀ ouvert et
    // actif ailleurs, on REFUSE la connexion. La personne peut quand même
    // forcer (si c'est bien elle) : dans ce cas l'autre page sera fermée.
    const dejaOuverte = sessionVivante(user.username);
    if (dejaOuverte && req.body.force !== true) {
      const depuis = Math.round((Date.now() - (dejaOuverte.session.lastSeen || 0)) / 1000);
      return res.status(409).json({
        error: 'Ce compte est déjà ouvert sur un autre appareil (actif il y a ' + depuis + ' s). Ferme-le d\'abord, ou force la connexion ici.',
        code: 'SESSION_ACTIVE',
        peutForcer: true
      });
    }

    const token = makeToken();
    // Toute autre session de ce compte est fermée immédiatement (l'ancienne
    // page sera renvoyée à la connexion en moins de 5 secondes).
    purgeUserSessions(user.username, 'Ton compte vient d\'être ouvert sur un autre appareil. Pour ta sécurité, cette page a été fermée.');
    sessions.set(token, {
      username: user.username, role: user.role,
      nomComplet: user.nom_complet, localiteId: user.localite_id || null,
      lastSeen: Date.now()
    });

    res.json({
      ok: true, token,
      username: user.username, role: user.role,
      nomComplet: user.nom_complet, localiteId: user.localite_id || null,
      mustChangePassword: user.must_change_password
    });
  } catch (e) {
    console.error('Erreur login:', e);
    res.status(500).json({ error: 'Erreur de connexion au serveur.' });
  }
});

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

// --- Vérifier le mot de passe (déverrouillage de l'écran après inactivité) ---
// Ne change PAS la session : la personne reprend son travail là où elle était.
app.post('/api/auth/verify-password', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT password_hash, password_salt, active FROM users WHERE username=$1', [req.session.username]);
    if (r.rows.length === 0 || !r.rows[0].active) {
      purgeUserSessions(req.session.username, 'Ce compte a été désactivé.');
      return res.status(401).json({ error: 'Compte désactivé.' });
    }
    const u = r.rows[0];
    const ok = verifyPassword(String(req.body.password || ''), u.password_hash, u.password_salt);
    if (!ok) return res.status(401).json({ error: 'Mot de passe incorrect.' });
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur vérification mdp:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, ...req.session });
});

// --- Synchronisation temps réel (appelée régulièrement par chaque client) ---
// Renvoie l'état FRAIS du compte (depuis la base) + la version des données.
// Si le compte a été désactivé ou supprimé, on répond 401 -> le client se déconnecte
// immédiatement, même s'il était en train de travailler.
app.get('/api/sync', requireAuth, async (req, res) => {
  try {
    // Signal de vie : c'est ce qui permet de savoir qu'une page est réellement
    // ouverte et utilisée, donc de bloquer une 2e connexion ailleurs.
    req.session.lastSeen = Date.now();
    const r = await pool.query(
      'SELECT nom_complet, role, localite_id, active FROM users WHERE username=$1',
      [req.session.username]
    );
    if (r.rows.length === 0 || !r.rows[0].active) {
      purgeUserSessions(req.session.username, 'Ton accès a été retiré par le Gérant.');
      return res.status(401).json({ error: 'Accès révoqué' });
    }
    const u = r.rows[0];
    // On rafraîchit la session en mémoire avec les valeurs à jour
    req.session.role = u.role;
    req.session.nomComplet = u.nom_complet;
    req.session.localiteId = u.localite_id || null;
    res.json({
      ok: true,
      role: u.role,
      nomComplet: u.nom_complet,
      localiteId: u.localite_id || null
    });
  } catch (e) {
    console.error('Erreur sync:', e);
    res.status(500).json({ error: 'sync impossible' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.slice(7);
  sessions.delete(token);
  res.json({ ok: true });
});

// =========================================================
//  LOCALITÉS (le Gérant crée et gère lui-même les localités)
// =========================================================
app.get('/api/localites', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, nom, active, created_at FROM localites ORDER BY created_at ASC');
    res.json(r.rows.map(l => ({ id: l.id, nom: l.nom, active: l.active, createdAt: l.created_at })));
  } catch (e) {
    console.error('Erreur lecture localités:', e);
    res.status(500).json({ error: 'lecture impossible' });
  }
});

app.post('/api/localites', requireAuth, requireGerant, async (req, res) => {
  try {
    const nom = String(req.body.nom || '').trim();
    if (!nom) return res.status(400).json({ error: 'Le nom de la localité est requis.' });
    const exists = await pool.query('SELECT 1 FROM localites WHERE LOWER(nom)=LOWER($1)', [nom]);
    if (exists.rows.length > 0) return res.status(409).json({ error: 'Cette localité existe déjà.' });
    const id = makeId();
    await pool.query('INSERT INTO localites (id, nom, active) VALUES ($1,$2,TRUE)', [id, nom]);
    res.json({ ok: true, id, nom, active: true });
  } catch (e) {
    console.error('Erreur création localité:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.patch('/api/localites/:id', requireAuth, requireGerant, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('SELECT * FROM localites WHERE id=$1', [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Localité introuvable.' });
    if (typeof req.body.nom === 'string' && req.body.nom.trim()) {
      await pool.query('UPDATE localites SET nom=$1 WHERE id=$2', [req.body.nom.trim(), id]);
    }
    if (typeof req.body.active === 'boolean') {
      await pool.query('UPDATE localites SET active=$1 WHERE id=$2', [req.body.active, id]);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur mise à jour localité:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.delete('/api/localites/:id', requireAuth, requireGerant, async (req, res) => {
  try {
    const id = req.params.id;
    // On détache d'abord les vendeurs affectés à cette localité
    await pool.query('UPDATE users SET localite_id=NULL WHERE localite_id=$1', [id]);
    await pool.query('DELETE FROM localites WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur suppression localité:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// =========================================================
//  GESTION DES COMPTES (réservé au Gérant)
// =========================================================
app.get('/api/users', requireAuth, requireGerant, async (req, res) => {
  const r = await pool.query(
    `SELECT u.username, u.nom_complet, u.role, u.localite_id, u.active, u.must_change_password, u.created_at,
            l.nom AS localite_nom
       FROM users u LEFT JOIN localites l ON l.id = u.localite_id
      ORDER BY u.created_at ASC`
  );
  res.json(r.rows.map(u => ({
    username: u.username,
    nomComplet: u.nom_complet,
    role: u.role,
    localiteId: u.localite_id || null,
    localiteNom: u.localite_nom || null,
    active: u.active,
    mustChangePassword: u.must_change_password,
    createdAt: u.created_at
  })));
});

app.post('/api/users', requireAuth, requireGerant, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const nomComplet = String(req.body.nomComplet || '').trim();
    const role = normalizeRole(req.body.role);
    let localiteId = req.body.localiteId ? String(req.body.localiteId) : null;

    if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
      return res.status(400).json({ error: "Identifiant invalide (3 à 30 caractères : lettres, chiffres, '.', '_', '-')." });
    }
    if (!nomComplet) return res.status(400).json({ error: 'Le nom complet est requis.' });

    // Un vendeur ou un caissier DOIT être rattaché à une localité active
    if (role === 'vente' || role === 'caisse') {
      if (!localiteId) return res.status(400).json({ error: 'Choisis la localité de ce compte.' });
      const loc = await pool.query('SELECT active FROM localites WHERE id=$1', [localiteId]);
      if (loc.rows.length === 0) return res.status(400).json({ error: 'Localité introuvable.' });
    } else {
      localiteId = null; // gérant / superviseur ne sont pas liés à une localité
    }

    const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
    if (exists.rows.length > 0) return res.status(409).json({ error: 'Cet identifiant existe déjà.' });

    const { hash, salt } = hashPassword(DEFAULT_PASSWORD);
    await pool.query(
      `INSERT INTO users (username, nom_complet, role, localite_id, password_hash, password_salt, must_change_password, active)
       VALUES ($1,$2,$3,$4,$5,$6,TRUE,TRUE)`,
      [username, nomComplet, role, localiteId, hash, salt]
    );
    res.json({ ok: true, username, nomComplet, role, localiteId, defaultPassword: DEFAULT_PASSWORD });
  } catch (e) {
    console.error('Erreur création compte:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.patch('/api/users/:username', requireAuth, requireGerant, async (req, res) => {
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
      if(req.body.active === false){ purgeUserSessions(username, 'Ton compte a été désactivé par le Gérant.'); } // déconnexion immédiate
    }
    if (ROLES.includes(req.body.role)) {
      const newRole = req.body.role;
      await pool.query('UPDATE users SET role=$1 WHERE username=$2', [newRole, username]);
      if (newRole !== 'vente') {
        await pool.query('UPDATE users SET localite_id=NULL WHERE username=$1', [username]);
      }
    }
    if (req.body.nomComplet) {
      await pool.query('UPDATE users SET nom_complet=$1 WHERE username=$2', [String(req.body.nomComplet).trim(), username]);
    }
    if (req.body.localiteId !== undefined) {
      const locId = req.body.localiteId ? String(req.body.localiteId) : null;
      await pool.query('UPDATE users SET localite_id=$1 WHERE username=$2', [locId, username]);
    }
    if (req.body.resetPassword === true) {
      const { hash, salt } = hashPassword(DEFAULT_PASSWORD);
      await pool.query(
        'UPDATE users SET password_hash=$1, password_salt=$2, must_change_password=TRUE WHERE username=$3',
        [hash, salt, username]
      );
    }

    // --- Application IMMÉDIATE sur les sessions ouvertes ---
    // On relit l'état à jour du compte, puis : si le compte est désactivé ou son mot
    // de passe réinitialisé -> on coupe ses sessions (il est éjecté sans attendre).
    // Sinon -> on met à jour ses droits en direct (rôle, nom, localité).
    const fresh = (await pool.query('SELECT * FROM users WHERE username=$1', [username])).rows[0];
    if (fresh) {
      if (!fresh.active || req.body.resetPassword === true) {
        killUserSessions(username);
      } else {
        patchUserSessions(username, {
          role: fresh.role,
          nomComplet: fresh.nom_complet,
          localiteId: fresh.localite_id || null
        });
      }
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur mise à jour compte:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.delete('/api/users/:username', requireAuth, requireGerant, async (req, res) => {
  try {
    const username = normalizeUsername(req.params.username);
    if (username === req.session.username) {
      return res.status(400).json({ error: 'Tu ne peux pas supprimer ton propre compte.' });
    }
    await pool.query('DELETE FROM users WHERE username=$1', [username]);
    purgeUserSessions(username, 'Ton compte a été supprimé par le Gérant.'); // déconnexion immédiate
    killUserSessions(username); // éjecte tout de suite s'il était connecté
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur suppression compte:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// =========================================================
//  DONNÉES DE L'APPLICATION (config : kits, articles, prix...)
// =========================================================
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT v FROM app_store WHERE k = $1', ['app-data']);
    if (r.rows.length === 0) return res.json(null);
    res.json(r.rows[0].v);
  } catch (e) {
    console.error('Erreur lecture:', e);
    res.status(500).json({ error: 'lecture impossible' });
  }
});

// Petit endpoint léger : donne juste la date de dernière modification.
// Les appareils l'interrogent souvent (c'est léger) pour savoir s'il faut se rafraîchir.
app.get('/api/data/meta', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT updated_at FROM app_store WHERE k = $1', ['app-data']);
    res.json({ updatedAt: r.rows.length ? r.rows[0].updated_at : null });
  } catch (e) {
    res.status(500).json({ error: 'meta impossible' });
  }
});

app.post('/api/data', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `INSERT INTO app_store (k, v, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = now()
       RETURNING updated_at`,
      ['app-data', req.body]
    );
    res.json({ ok: true, updatedAt: r.rows[0].updated_at });
  } catch (e) {
    console.error('Erreur écriture:', e);
    res.status(500).json({ error: 'sauvegarde impossible' });
  }
});

// =========================================================
//  TRANSACTIONS ATOMIQUES (plusieurs ventes en même temps)
// =========================================================
// Problème résolu ici : si deux caisses enregistrent à la même seconde, la
// dernière sauvegarde ne doit PAS écraser l'autre. On applique donc chaque
// opération sensible (commande, paiement, réception, transfert) DIRECTEMENT
// sur le serveur, dans une transaction avec verrou (SELECT ... FOR UPDATE).
// Les opérations s'exécutent alors une par une, à la file : aucune perte.
async function withAppData(mutator) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Le verrou : la 2e caisse attend ici que la 1ère ait fini. Quelques
    // millisecondes, invisible pour l'utilisateur, mais rien ne se perd.
    const r = await client.query('SELECT v FROM app_store WHERE k=$1 FOR UPDATE', ['app-data']);
    if (r.rows.length === 0) { await client.query('ROLLBACK'); throw new Error('Données introuvables'); }
    const data = r.rows[0].v;
    const result = mutator(data); // peut lever une erreur métier (stock insuffisant...)
    await client.query(
      `INSERT INTO app_store (k, v, updated_at) VALUES ($1,$2, now())
       ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = now()`,
      ['app-data', data]
    );
    await client.query('COMMIT');
    return result;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally {
    client.release();
  }
}

function newId(){ return crypto.randomBytes(9).toString('hex'); }

// --- 1) Créer une commande + réserver le stock de la boutique (atomique) ---
app.post('/api/tx/commande', requireAuth, async (req, res) => {
  try {
    const { localiteId, localiteNom, lignes, besoins, total, clientNom, clientTel } = req.body;
    if (!localiteId || !Array.isArray(lignes) || lignes.length === 0) {
      return res.status(400).json({ error: 'Commande invalide.' });
    }
    // Un vendeur ne peut commander que dans SA boutique
    if (req.session.role === 'vente' && req.session.localiteId !== localiteId) {
      return res.status(403).json({ error: 'Boutique non autorisée.' });
    }
    const out = await withAppData(data => {
      data.stockLoc = data.stockLoc || {};
      data.stockLoc[localiteId] = data.stockLoc[localiteId] || {};
      data.commandesVente = data.commandesVente || [];
      const st = data.stockLoc[localiteId];
      // Vérification du stock AVEC les données fraîches du serveur
      const manquants = [];
      Object.keys(besoins || {}).forEach(ref => {
        if ((st[ref] || 0) < besoins[ref]) manquants.push(ref);
      });
      if (manquants.length) {
        const err = new Error('STOCK_INSUFFISANT');
        err.refs = manquants;
        throw err;
      }
      Object.keys(besoins || {}).forEach(ref => { st[ref] = (st[ref] || 0) - besoins[ref]; });
      // Code unique parmi les commandes en attente de CETTE boutique
      const pris = data.commandesVente.filter(c => c.statut === 'en_attente').map(c => c.code);
      let code;
      do { code = String(Math.floor(1000 + Math.random() * 9000)); } while (pris.includes(code));
      data.commandeSeq = (data.commandeSeq || 0) + 1;
      const now = new Date();
      const cmd = {
        id: newId(), code, num: 'CMD-' + String(data.commandeSeq).padStart(4, '0'),
        localiteId, localiteNom: localiteNom || '',
        agent: req.session.nomComplet || req.session.username,
        agentUsername: req.session.username,
        date: now.toISOString().slice(0, 10),
        heure: now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        lignes, besoins: besoins || {}, total: Number(total) || 0, statut: 'en_attente',
        clientNom: String(clientNom || '').slice(0, 80),
        clientTel: String(clientTel || '').slice(0, 30)
      };
      data.commandesVente.unshift(cmd);
      return cmd;
    });
    res.json({ ok: true, commande: out });
  } catch (e) {
    if (e.message === 'STOCK_INSUFFISANT') {
      return res.status(409).json({ error: 'Stock insuffisant en boutique', refs: e.refs });
    }
    console.error('Erreur commande:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- 2) Encaisser une commande par son code (atomique) ---
app.post('/api/tx/payer', requireAuth, async (req, res) => {
  try {
    const { code, localiteId, montantRecu, ventes, ventesLivres } = req.body;
    if (req.session.role === 'caisse' && req.session.localiteId !== localiteId) {
      return res.status(403).json({ error: 'Boutique non autorisée.' });
    }
    const out = await withAppData(data => {
      data.commandesVente = data.commandesVente || [];
      data.ventes = data.ventes || [];
      data.ventesLivres = data.ventesLivres || [];
      const c = data.commandesVente.find(x => x.code === code && x.localiteId === localiteId && x.statut === 'en_attente');
      // Si elle n'est plus "en attente", c'est qu'une autre caisse vient de l'encaisser.
      if (!c) { throw new Error('COMMANDE_INTROUVABLE'); }
      const recu = Number(montantRecu);
      if (isNaN(recu) || recu < c.total) { throw new Error('MONTANT_INSUFFISANT'); }
      const now = new Date();
      c.statut = 'payee';
      c.montantRecu = recu;
      c.monnaie = recu - c.total;
      c.caissier = req.session.nomComplet || req.session.username;
      c.caissierUsername = req.session.username;
      c.paidAt = now.toISOString();
      c.paidDate = now.toISOString().slice(0, 10);
      c.paidHeure = now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
      // Les ventes (recette) sont ajoutées ici, côté serveur : rien ne se perd
      (ventes || []).forEach(v => {
        data.ventes.push({ ...v, id: newId(), date: c.paidDate, heure: c.paidHeure, localiteId: c.localiteId });
      });
      (ventesLivres || []).forEach(v => {
        data.ventesLivres.push({ ...v, id: newId(), date: c.paidDate, heure: c.paidHeure, localiteId: c.localiteId });
      });
      return c;
    });
    res.json({ ok: true, commande: out });
  } catch (e) {
    if (e.message === 'COMMANDE_INTROUVABLE') return res.status(409).json({ error: 'Cette commande a déjà été encaissée ou annulée.' });
    if (e.message === 'MONTANT_INSUFFISANT') return res.status(400).json({ error: 'Montant reçu insuffisant.' });
    console.error('Erreur paiement:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- 3) Annuler une commande et rendre le stock (atomique) ---
app.post('/api/tx/annuler', requireAuth, async (req, res) => {
  try {
    const { cmdId } = req.body;
    const out = await withAppData(data => {
      const c = (data.commandesVente || []).find(x => x.id === cmdId && x.statut === 'en_attente');
      if (!c) throw new Error('COMMANDE_INTROUVABLE');
      if (req.session.role === 'vente' && req.session.localiteId !== c.localiteId) throw new Error('INTERDIT');
      data.stockLoc = data.stockLoc || {};
      data.stockLoc[c.localiteId] = data.stockLoc[c.localiteId] || {};
      Object.keys(c.besoins || {}).forEach(ref => {
        data.stockLoc[c.localiteId][ref] = (data.stockLoc[c.localiteId][ref] || 0) + c.besoins[ref];
      });
      c.statut = 'annulee';
      c.annuleeAt = new Date().toISOString();
      c.annulePar = req.session.nomComplet || req.session.username;
      return c;
    });
    res.json({ ok: true, commande: out });
  } catch (e) {
    if (e.message === 'COMMANDE_INTROUVABLE') return res.status(409).json({ error: 'Commande déjà encaissée ou annulée.' });
    if (e.message === 'INTERDIT') return res.status(403).json({ error: 'Non autorisé.' });
    console.error('Erreur annulation:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- 4) Réception fournisseur (atomique) ---
app.post('/api/tx/reception', requireAuth, requireGerant, async (req, res) => {
  try {
    const { lignes, fournisseurId, fournisseurNom, dateISO } = req.body;
    if (!Array.isArray(lignes) || lignes.length === 0) return res.status(400).json({ error: 'Réception vide.' });
    const out = await withAppData(data => {
      data.receptions = data.receptions || [];
      lignes.forEach(l => {
        const coll = l.kind === 'art' ? data.articles : (data.livres || []);
        const item = coll.find(x => x.id === l.id);
        if (item) { item.stock = (item.stock || 0) + l.qte; if (l.prixAchat) item.prixAchat = l.prixAchat; }
      });
      data.receptionSeq = (data.receptionSeq || 0) + 1;
      const d = dateISO || new Date().toISOString().slice(0, 10);
      const now = new Date();
      const rec = {
        id: newId(), num: 'BR-' + d.replace(/-/g, '') + '-' + String(data.receptionSeq).padStart(4, '0'),
        date: new Date(d + 'T00:00:00').toLocaleDateString('fr-FR'), dateISO: d,
        heure: now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        fournisseurId: fournisseurId || null, fournisseurNom: fournisseurNom || '',
        lignes, totalQte: lignes.reduce((s, l) => s + l.qte, 0),
        totalMontant: lignes.reduce((s, l) => s + l.qte * (l.prixAchat || 0), 0),
        agent: req.session.nomComplet || req.session.username
      };
      data.receptions.unshift(rec);
      return rec;
    });
    res.json({ ok: true, reception: out });
  } catch (e) {
    console.error('Erreur réception:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- 5) Transfert vers une boutique (atomique) ---
app.post('/api/tx/transfert', requireAuth, requireGerant, async (req, res) => {
  try {
    const { localiteId, localiteNom, lignes } = req.body;
    if (!localiteId || !Array.isArray(lignes) || lignes.length === 0) return res.status(400).json({ error: 'Transfert vide.' });
    const out = await withAppData(data => {
      data.stockLoc = data.stockLoc || {};
      data.stockLoc[localiteId] = data.stockLoc[localiteId] || {};
      data.transferts = data.transferts || [];
      // Vérifier le grand stock avec les données fraîches
      const manquants = [];
      lignes.forEach(l => {
        const coll = l.kind === 'art' ? data.articles : (data.livres || []);
        const item = coll.find(x => x.id === l.id);
        if (!item || (item.stock || 0) < l.qte) manquants.push(l.nom || l.id);
      });
      if (manquants.length) { const err = new Error('STOCK_INSUFFISANT'); err.noms = manquants; throw err; }
      lignes.forEach(l => {
        const coll = l.kind === 'art' ? data.articles : (data.livres || []);
        const item = coll.find(x => x.id === l.id);
        item.stock -= l.qte;
        const ref = l.kind + ':' + l.id;
        data.stockLoc[localiteId][ref] = (data.stockLoc[localiteId][ref] || 0) + l.qte;
      });
      data.transfertSeq = (data.transfertSeq || 0) + 1;
      const now = new Date();
      const t = {
        id: newId(), num: 'BT-' + now.toISOString().slice(0, 10).replace(/-/g, '') + '-' + String(data.transfertSeq).padStart(4, '0'),
        date: now.toLocaleDateString('fr-FR'), heure: now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        localiteId, localiteNom: localiteNom || '', lignes,
        totalQte: lignes.reduce((s, l) => s + l.qte, 0),
        agent: req.session.nomComplet || req.session.username
      };
      data.transferts.unshift(t);
      return t;
    });
    res.json({ ok: true, transfert: out });
  } catch (e) {
    if (e.message === 'STOCK_INSUFFISANT') return res.status(409).json({ error: 'Grand stock insuffisant : ' + (e.noms || []).slice(0, 3).join(', ') });
    console.error('Erreur transfert:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// =========================================================
//  SANTÉ DU SERVEUR (pour l'empêcher de s'endormir)
// =========================================================
// Render met le service en veille après ~15 min sans visite. Un service
// extérieur (cron-job.org, UptimeRobot...) appelle cette adresse toutes les
// 10 minutes : le serveur reste éveillé et le premier vendeur du matin
// n'attend pas. Volontairement très léger et sans authentification.
app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'shiphra', time: new Date().toISOString() });
});

// Version qui vérifie AUSSI que la base répond (utile pour surveiller).
app.get('/health/db', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'connectée', time: new Date().toISOString() });
  } catch (e) {
    console.error('Health DB:', e.message);
    res.status(503).json({ ok: false, db: 'injoignable' });
  }
});

// =========================================================
//  SAUVEGARDE AUTOMATIQUE PAR EMAIL (protection des données)
// =========================================================
// Chaque jour, toutes les données (ventes, stock, kits, transactions...) sont
// envoyées en pièce jointe à l'adresse ci-dessous. Si la base Render est
// perdue ou expire, tu gardes TOUT dans ta boîte mail.
const BACKUP_EMAIL = process.env.BACKUP_EMAIL || 'neildexter3001@gmail.com';

function makeTransport() {
  // Nécessite 2 variables d'environnement sur Render :
  //   SMTP_USER = ton adresse Gmail
  //   SMTP_PASS = un "mot de passe d'application" Google (16 lettres)
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  let nodemailer;
  try { nodemailer = require('nodemailer'); }
  catch (e) { console.warn('nodemailer non installé : ajoute-le dans package.json'); return null; }
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

async function envoyerSauvegarde(motif) {
  const transport = makeTransport();
  if (!transport) {
    console.warn('Sauvegarde email non configurée (SMTP_USER / SMTP_PASS manquants).');
    return { ok: false, error: 'Email non configuré sur le serveur (SMTP_USER / SMTP_PASS).' };
  }
  const r = await pool.query('SELECT v, updated_at FROM app_store WHERE k=$1', ['app-data']);
  if (r.rows.length === 0) return { ok: false, error: 'Aucune donnée à sauvegarder.' };
  const data = r.rows[0].v;
  const users = await pool.query('SELECT username, nom_complet, role, localite_id, active FROM users');
  const locs = await pool.query('SELECT id, nom, active FROM localites');

  const backup = {
    genereLe: new Date().toISOString(),
    motif: motif || 'automatique',
    donnees: data,
    comptes: users.rows,     // sans les mots de passe : jamais dans un mail
    localites: locs.rows
  };
  const jour = new Date().toISOString().slice(0, 10);
  const json = JSON.stringify(backup, null, 2);

  // Petit résumé lisible dans le corps du mail
  const nbVentes = (data.ventes || []).length + (data.ventesLivres || []).length;
  const payees = (data.commandesVente || []).filter(c => c.statut === 'payee');
  const totalEncaisse = payees.reduce((s, c) => s + (c.total || 0), 0);

  await transport.sendMail({
    from: process.env.SMTP_USER,
    to: BACKUP_EMAIL,
    subject: `Sauvegarde Shiphra Business Center — ${jour}`,
    text:
`Sauvegarde automatique de Shiphra Business Center.

Date : ${jour}
Ventes enregistrées : ${nbVentes}
Transactions payées : ${payees.length}
Total encaissé (historique) : ${totalEncaisse.toLocaleString('fr-FR')} F
Kits configurés : ${(data.niveaux || []).length}
Articles : ${(data.articles || []).length}
Livres : ${(data.livres || []).length}
Localités : ${locs.rows.length}
Comptes : ${users.rows.length}

Le fichier joint contient TOUTES les données.
Garde ce mail : il permet de tout restaurer si la base est perdue.`,
    attachments: [{ filename: `shiphra-sauvegarde-${jour}.json`, content: json }]
  });
  console.log('Sauvegarde envoyée à', BACKUP_EMAIL);
  return { ok: true, email: BACKUP_EMAIL, taille: json.length };
}

// --- Envoi manuel (bouton dans l'application, réservé au Gérant) ---
app.post('/api/backup/now', requireAuth, requireGerant, async (req, res) => {
  try {
    const out = await envoyerSauvegarde('manuelle');
    if (!out.ok) return res.status(400).json(out);
    res.json(out);
  } catch (e) {
    console.error('Erreur sauvegarde:', e);
    res.status(500).json({ ok: false, error: "Envoi impossible : " + e.message });
  }
});

// --- Téléchargement direct (filet de sécurité, sans dépendre du mail) ---
app.get('/api/backup/download', requireAuth, requireGerant, async (req, res) => {
  try {
    const r = await pool.query('SELECT v FROM app_store WHERE k=$1', ['app-data']);
    const locs = await pool.query('SELECT id, nom, active FROM localites ORDER BY created_at ASC');
    const jour = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Disposition', `attachment; filename="shiphra-sauvegarde-${jour}.json"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify({
      genereLe: new Date().toISOString(),
      version: 'v6',
      donnees: r.rows[0] ? r.rows[0].v : null,
      localites: locs.rows
    }, null, 2));
  } catch (e) {
    res.status(500).json({ error: 'Téléchargement impossible' });
  }
});

// --- RESTAURATION (déménagement de base / récupération après incident) ---
// Le Gérant envoie un fichier de sauvegarde : on remet les données et les
// localités en place. Les comptes ne sont PAS restaurés (les mots de passe ne
// voyagent jamais) : ils se recréent en 1 minute dans « Comptes équipe ».
app.post('/api/backup/restore', requireAuth, requireGerant, async (req, res) => {
  const client = await pool.connect();
  try {
    const { donnees, localites, confirmer } = req.body;
    if (confirmer !== 'RESTAURER') return res.status(400).json({ error: 'Confirmation manquante.' });
    if (!donnees || typeof donnees !== 'object') return res.status(400).json({ error: 'Fichier de sauvegarde invalide ou illisible.' });

    await client.query('BEGIN');
    // 1) Les localités d'abord : leurs identifiants sont utilisés par les stocks
    if (Array.isArray(localites)) {
      for (const l of localites) {
        if (!l || !l.id || !l.nom) continue;
        await client.query(
          `INSERT INTO localites (id, nom, active) VALUES ($1,$2,$3)
           ON CONFLICT (id) DO UPDATE SET nom = EXCLUDED.nom, active = EXCLUDED.active`,
          [String(l.id), String(l.nom), l.active !== false]
        );
      }
    }
    // 2) Puis toutes les données de l'application
    await client.query(
      `INSERT INTO app_store (k, v, updated_at) VALUES ($1,$2, now())
       ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = now()`,
      ['app-data', donnees]
    );
    await client.query('COMMIT');

    const resume = {
      ventes: (donnees.ventes || []).length,
      ventesLivres: (donnees.ventesLivres || []).length,
      transactions: (donnees.commandesVente || []).length,
      articles: (donnees.articles || []).length,
      livres: (donnees.livres || []).length,
      kits: (donnees.niveaux || []).length,
      localites: Array.isArray(localites) ? localites.length : 0
    };
    console.log('Restauration effectuée par', req.session.username, resume);
    res.json({ ok: true, resume });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('Erreur restauration:', e);
    res.status(500).json({ error: 'Restauration impossible : ' + e.message });
  } finally {
    client.release();
  }
});

// --- Planificateur : une sauvegarde par jour, automatiquement ---
// On vérifie toutes les 30 minutes s'il est l'heure (20h, heure d'Abidjan)
// et si la sauvegarde du jour n'a pas déjà été envoyée.
let dernierJourSauvegarde = null;
function planifierSauvegardes() {
  const HEURE_SAUVEGARDE = Number(process.env.BACKUP_HOUR || 20); // 20h par défaut
  setInterval(async () => {
    try {
      const maintenant = new Date();
      const jour = maintenant.toISOString().slice(0, 10);
      const heure = maintenant.getUTCHours(); // Abidjan = UTC+0
      if (heure === HEURE_SAUVEGARDE && dernierJourSauvegarde !== jour) {
        dernierJourSauvegarde = jour;
        await envoyerSauvegarde('quotidienne');
      }
    } catch (e) {
      console.error('Sauvegarde quotidienne échouée:', e.message);
    }
  }, 30 * 60 * 1000);
  console.log('Sauvegarde quotidienne planifiée à ' + HEURE_SAUVEGARDE + 'h vers ' + BACKUP_EMAIL);
}

// --- 6) RETOUR : boutique -> grand stock (marchandise rendue au Gérant) ---
app.post('/api/tx/retour-boutique', requireAuth, async (req, res) => {
  try {
    const { localiteId, localiteNom, lignes, motif } = req.body;
    if (!localiteId || !Array.isArray(lignes) || lignes.length === 0) return res.status(400).json({ error: 'Retour vide.' });
    // Un vendeur/caissier ne peut retourner QUE depuis sa propre boutique
    if ((req.session.role === 'vente' || req.session.role === 'caisse') && req.session.localiteId !== localiteId) {
      return res.status(403).json({ error: 'Boutique non autorisée.' });
    }
    const out = await withAppData(data => {
      data.stockLoc = data.stockLoc || {};
      data.stockLoc[localiteId] = data.stockLoc[localiteId] || {};
      data.retours = data.retours || [];
      const st = data.stockLoc[localiteId];
      // Vérification avec les données FRAÎCHES du serveur
      const manquants = [];
      lignes.forEach(l => {
        const ref = l.kind + ':' + l.id;
        if ((st[ref] || 0) < l.qte) manquants.push(l.nom || ref);
      });
      if (manquants.length) { const err = new Error('STOCK_INSUFFISANT'); err.noms = manquants; throw err; }
      // La boutique baisse, le grand stock remonte
      lignes.forEach(l => {
        const ref = l.kind + ':' + l.id;
        st[ref] = (st[ref] || 0) - l.qte;
        const coll = l.kind === 'art' ? data.articles : (data.livres || []);
        const item = coll.find(x => x.id === l.id);
        if (item) item.stock = (item.stock || 0) + l.qte;
      });
      data.retourSeq = (data.retourSeq || 0) + 1;
      const now = new Date();
      const r = {
        id: newId(), type: 'boutique',
        num: 'RB-' + now.toISOString().slice(0, 10).replace(/-/g, '') + '-' + String(data.retourSeq).padStart(4, '0'),
        date: now.toLocaleDateString('fr-FR'), dateISO: now.toISOString().slice(0, 10),
        heure: now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        localiteId, localiteNom: localiteNom || '',
        motif: String(motif || '').slice(0, 200),
        lignes, totalQte: lignes.reduce((s, l) => s + l.qte, 0),
        agent: req.session.nomComplet || req.session.username
      };
      data.retours.unshift(r);
      return r;
    });
    res.json({ ok: true, retour: out });
  } catch (e) {
    if (e.message === 'STOCK_INSUFFISANT') return res.status(409).json({ error: 'Stock boutique insuffisant : ' + (e.noms || []).slice(0, 3).join(', ') });
    console.error('Erreur retour boutique:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- 7) RETOUR : grand stock -> fournisseur (marchandise rendue au fournisseur) ---
app.post('/api/tx/retour-fournisseur', requireAuth, requireGerant, async (req, res) => {
  try {
    const { fournisseurId, fournisseurNom, lignes, motif } = req.body;
    if (!Array.isArray(lignes) || lignes.length === 0) return res.status(400).json({ error: 'Retour vide.' });
    const out = await withAppData(data => {
      data.retours = data.retours || [];
      const manquants = [];
      lignes.forEach(l => {
        const coll = l.kind === 'art' ? data.articles : (data.livres || []);
        const item = coll.find(x => x.id === l.id);
        if (!item || (item.stock || 0) < l.qte) manquants.push(l.nom || l.id);
      });
      if (manquants.length) { const err = new Error('STOCK_INSUFFISANT'); err.noms = manquants; throw err; }
      lignes.forEach(l => {
        const coll = l.kind === 'art' ? data.articles : (data.livres || []);
        const item = coll.find(x => x.id === l.id);
        item.stock -= l.qte;
      });
      data.retourSeq = (data.retourSeq || 0) + 1;
      const now = new Date();
      const r = {
        id: newId(), type: 'fournisseur',
        num: 'RF-' + now.toISOString().slice(0, 10).replace(/-/g, '') + '-' + String(data.retourSeq).padStart(4, '0'),
        date: now.toLocaleDateString('fr-FR'), dateISO: now.toISOString().slice(0, 10),
        heure: now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        fournisseurId: fournisseurId || null, fournisseurNom: fournisseurNom || '',
        motif: String(motif || '').slice(0, 200),
        lignes, totalQte: lignes.reduce((s, l) => s + l.qte, 0),
        totalMontant: lignes.reduce((s, l) => s + l.qte * (l.prixAchat || 0), 0),
        agent: req.session.nomComplet || req.session.username
      };
      data.retours.unshift(r);
      return r;
    });
    res.json({ ok: true, retour: out });
  } catch (e) {
    if (e.message === 'STOCK_INSUFFISANT') return res.status(409).json({ error: 'Grand stock insuffisant : ' + (e.noms || []).slice(0, 3).join(', ') });
    console.error('Erreur retour fournisseur:', e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- Démarrage ---
// On ouvre le port QUOI QU'IL ARRIVE : si l'initialisation de la base rencontre
// un souci, le serveur démarre quand même (Render détecte le port) et l'erreur
// est écrite dans les logs pour qu'on puisse la voir sans que le service tombe.
const PORT = process.env.PORT || 3000;
init()
  .then(() => console.log('Initialisation de la base : OK.'))
  .catch(e => console.error('Initialisation de la base : ÉCHEC (le serveur démarre quand même) ->', e))
  .finally(() => {
    app.listen(PORT, () => console.log('Serveur démarré sur le port ' + PORT));
    // Garde la connexion à la base bien vivante tant que le serveur tourne.
    // (N'empêche PAS Render d'endormir le service : pour ça il faut un appel
    //  EXTÉRIEUR sur /health — voir cron-job.org.)
    setInterval(() => {
      pool.query('SELECT 1').catch(e => console.warn('Ping base échoué:', e.message));
    }, 4 * 60 * 1000);
    planifierSauvegardes(); // sauvegarde automatique quotidienne par email
  });
