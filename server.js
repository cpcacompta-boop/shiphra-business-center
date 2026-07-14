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
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Mot de passe temporaire donné à tout nouveau compte
const DEFAULT_PASSWORD = '0000';

// Sessions en mémoire (token -> { username, role, nomComplet, localiteId })
const sessions = new Map();

// Déconnecte immédiatement toutes les sessions ouvertes d'un utilisateur
// (utilisé quand on le désactive ou le supprime : effet instantané).
function purgeUserSessions(username){
  for(const [tok, s] of sessions){ if(s.username === username) sessions.delete(tok); }
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

const ROLES = ['gerant', 'superviseur', 'vente'];
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
  if (!session) return res.status(401).json({ error: 'Non authentifié' });
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

    const token = makeToken();
    sessions.set(token, {
      username: user.username, role: user.role,
      nomComplet: user.nom_complet, localiteId: user.localite_id || null
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

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, ...req.session });
});

// --- Synchronisation temps réel (appelée régulièrement par chaque client) ---
// Renvoie l'état FRAIS du compte (depuis la base) + la version des données.
// Si le compte a été désactivé ou supprimé, on répond 401 -> le client se déconnecte
// immédiatement, même s'il était en train de travailler.
app.get('/api/sync', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT nom_complet, role, localite_id, active FROM users WHERE username=$1',
      [req.session.username]
    );
    if (r.rows.length === 0 || !r.rows[0].active) {
      purgeUserSessions(req.session.username);
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

    // Un vendeur DOIT être rattaché à une localité active
    if (role === 'vente') {
      if (!localiteId) return res.status(400).json({ error: 'Choisis la localité du vendeur.' });
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
      if(req.body.active === false){ purgeUserSessions(username); } // déconnexion immédiate
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
    purgeUserSessions(username); // déconnexion immédiate
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
  });
