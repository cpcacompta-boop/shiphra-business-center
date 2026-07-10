// ============================================================
//  Shiphra Business Center — Serveur (Express + PostgreSQL)
//  Sert l'application et enregistre toutes les données en base.
// ============================================================

const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '5mb' }));           // accepte les grosses sauvegardes JSON
app.use(express.static(path.join(__dirname, 'public'))); // sert public/index.html

// --- Connexion à la base PostgreSQL de Render ---
// La variable DATABASE_URL est fournie automatiquement par Render (voir les étapes).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- Création automatique de la table au démarrage ---
async function init(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_store (
      k TEXT PRIMARY KEY,
      v JSONB NOT NULL
    )
  `);
  console.log('Table app_store prête.');
}

// --- Lire les données (ventes, stock, dépenses...) ---
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

// --- Enregistrer les données ---
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