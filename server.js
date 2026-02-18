const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || 'admin1234';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ── Database Setup ──────────────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || './gamedata.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS players (
    id TEXT PRIMARY KEY,
    game_id TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    token TEXT,
    credits INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(game_id, username)
  );

  CREATE TABLE IF NOT EXISTS player_data (
    player_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    PRIMARY KEY (player_id, key),
    FOREIGN KEY (player_id) REFERENCES players(id)
  );

  CREATE TABLE IF NOT EXISTS cosmetics_catalog (
    id TEXT PRIMARY KEY,
    game_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    price INTEGER DEFAULT 0,
    rarity TEXT DEFAULT 'common',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS player_cosmetics (
    player_id TEXT NOT NULL,
    cosmetic_id TEXT NOT NULL,
    equipped INTEGER DEFAULT 0,
    obtained_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (player_id, cosmetic_id)
  );

  CREATE TABLE IF NOT EXISTS inventory (
    player_id TEXT NOT NULL,
    item_name TEXT NOT NULL,
    quantity INTEGER DEFAULT 1,
    metadata TEXT,
    PRIMARY KEY (player_id, item_name)
  );

  CREATE TABLE IF NOT EXISTS broadcast_messages (
    id TEXT PRIMARY KEY,
    game_id TEXT,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ── Helpers ─────────────────────────────────────────────────────────────────
function getPlayer(token) {
  return db.prepare('SELECT * FROM players WHERE token = ?').get(token);
}

function requireAuth(req, res, next) {
  const token = req.headers['x-player-token'] || req.body?.token;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  const player = getPlayer(token);
  if (!player) return res.status(401).json({ error: 'Invalid token' });
  if (player.banned) return res.status(403).json({ error: 'Account banned' });
  req.player = player;
  next();
}

function requireOwner(req, res, next) {
  const key = req.headers['x-owner-key'] || req.body?.owner_key;
  if (key !== OWNER_PASSWORD) return res.status(403).json({ error: 'Not authorized' });
  next();
}

// ── Auth Routes ──────────────────────────────────────────────────────────────

// POST /register
app.post('/register', (req, res) => {
  const { game_id, username, password } = req.body;
  if (!game_id || !username || !password)
    return res.status(400).json({ error: 'game_id, username, and password required' });

  const hash = bcrypt.hashSync(password, 10);
  const id = uuidv4();
  const token = uuidv4();

  try {
    db.prepare('INSERT INTO players (id, game_id, username, password_hash, token) VALUES (?,?,?,?,?)')
      .run(id, game_id, username, hash, token);
    res.json({ success: true, player_id: id, token, username, credits: 0 });
  } catch (e) {
    res.status(409).json({ error: 'Username already taken in this game' });
  }
});

// POST /login
app.post('/login', (req, res) => {
  const { game_id, username, password } = req.body;
  if (!game_id || !username || !password)
    return res.status(400).json({ error: 'game_id, username, and password required' });

  const player = db.prepare('SELECT * FROM players WHERE game_id = ? AND username = ?').get(game_id, username);
  if (!player || !bcrypt.compareSync(password, player.password_hash))
    return res.status(401).json({ error: 'Invalid credentials' });
  if (player.banned) return res.status(403).json({ error: 'Account banned' });

  const token = uuidv4();
  db.prepare('UPDATE players SET token = ? WHERE id = ?').run(token, player.id);
  res.json({ success: true, player_id: player.id, token, username: player.username, credits: player.credits });
});

// GET /me
app.get('/me', requireAuth, (req, res) => {
  const { id, game_id, username, credits, created_at } = req.player;
  res.json({ player_id: id, game_id, username, credits, created_at });
});

// ── Save Data Routes ─────────────────────────────────────────────────────────

// POST /save  — save any key/value JSON data
app.post('/save', requireAuth, (req, res) => {
  const { data } = req.body;
  if (!data || typeof data !== 'object')
    return res.status(400).json({ error: 'data must be a JSON object' });

  const upsert = db.prepare('INSERT OR REPLACE INTO player_data (player_id, key, value) VALUES (?,?,?)');
  const tx = db.transaction((entries) => {
    for (const [key, value] of entries) {
      upsert.run(req.player.id, key, JSON.stringify(value));
    }
  });
  tx(Object.entries(data));
  res.json({ success: true });
});

// GET /load  — load all saved data
app.get('/load', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM player_data WHERE player_id = ?').all(req.player.id);
  const data = {};
  for (const row of rows) {
    try { data[row.key] = JSON.parse(row.value); } catch { data[row.key] = row.value; }
  }
  res.json({ success: true, data });
});

// DELETE /save/:key  — delete a specific save key
app.delete('/save/:key', requireAuth, (req, res) => {
  db.prepare('DELETE FROM player_data WHERE player_id = ? AND key = ?').run(req.player.id, req.params.key);
  res.json({ success: true });
});

// ── Credits Routes ───────────────────────────────────────────────────────────

// GET /credits
app.get('/credits', requireAuth, (req, res) => {
  res.json({ success: true, credits: req.player.credits });
});

// POST /credits/spend
app.post('/credits/spend', requireAuth, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  if (req.player.credits < amount) return res.status(400).json({ error: 'Not enough credits' });
  db.prepare('UPDATE players SET credits = credits - ? WHERE id = ?').run(amount, req.player.id);
  const updated = db.prepare('SELECT credits FROM players WHERE id = ?').get(req.player.id);
  res.json({ success: true, credits: updated.credits });
});

// POST /credits/add  (owner only in production — or you can use it from game for rewards)
app.post('/credits/add', requireAuth, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  db.prepare('UPDATE players SET credits = credits + ? WHERE id = ?').run(amount, req.player.id);
  const updated = db.prepare('SELECT credits FROM players WHERE id = ?').get(req.player.id);
  res.json({ success: true, credits: updated.credits });
});

// ── Inventory Routes ─────────────────────────────────────────────────────────

// GET /inventory
app.get('/inventory', requireAuth, (req, res) => {
  const items = db.prepare('SELECT item_name, quantity, metadata FROM inventory WHERE player_id = ?').all(req.player.id);
  res.json({ success: true, inventory: items });
});

// POST /inventory/add
app.post('/inventory/add', requireAuth, (req, res) => {
  const { item_name, quantity = 1, metadata } = req.body;
  if (!item_name) return res.status(400).json({ error: 'item_name required' });
  db.prepare(`
    INSERT INTO inventory (player_id, item_name, quantity, metadata)
    VALUES (?,?,?,?)
    ON CONFLICT(player_id, item_name) DO UPDATE SET quantity = quantity + excluded.quantity
  `).run(req.player.id, item_name, quantity, metadata ? JSON.stringify(metadata) : null);
  res.json({ success: true });
});

// POST /inventory/remove
app.post('/inventory/remove', requireAuth, (req, res) => {
  const { item_name, quantity = 1 } = req.body;
  if (!item_name) return res.status(400).json({ error: 'item_name required' });
  const item = db.prepare('SELECT quantity FROM inventory WHERE player_id = ? AND item_name = ?').get(req.player.id, item_name);
  if (!item) return res.status(404).json({ error: 'Item not found' });
  if (item.quantity <= quantity) {
    db.prepare('DELETE FROM inventory WHERE player_id = ? AND item_name = ?').run(req.player.id, item_name);
  } else {
    db.prepare('UPDATE inventory SET quantity = quantity - ? WHERE player_id = ? AND item_name = ?').run(quantity, req.player.id, item_name);
  }
  res.json({ success: true });
});

// ── Cosmetics Routes ─────────────────────────────────────────────────────────

// GET /cosmetics/catalog  — get all cosmetics for a game
app.get('/cosmetics/catalog', (req, res) => {
  const { game_id } = req.query;
  if (!game_id) return res.status(400).json({ error: 'game_id query param required' });
  const items = db.prepare('SELECT * FROM cosmetics_catalog WHERE game_id = ?').all(game_id);
  res.json({ success: true, cosmetics: items });
});

// GET /cosmetics/owned  — get cosmetics the player owns
app.get('/cosmetics/owned', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*, pc.equipped, pc.obtained_at
    FROM player_cosmetics pc
    JOIN cosmetics_catalog c ON c.id = pc.cosmetic_id
    WHERE pc.player_id = ?
  `).all(req.player.id);
  res.json({ success: true, cosmetics: rows });
});

// POST /cosmetics/buy  — buy a cosmetic with credits
app.post('/cosmetics/buy', requireAuth, (req, res) => {
  const { cosmetic_id } = req.body;
  if (!cosmetic_id) return res.status(400).json({ error: 'cosmetic_id required' });

  const cosmetic = db.prepare('SELECT * FROM cosmetics_catalog WHERE id = ?').get(cosmetic_id);
  if (!cosmetic) return res.status(404).json({ error: 'Cosmetic not found' });

  const already = db.prepare('SELECT 1 FROM player_cosmetics WHERE player_id = ? AND cosmetic_id = ?').get(req.player.id, cosmetic_id);
  if (already) return res.status(409).json({ error: 'Already owned' });

  if (req.player.credits < cosmetic.price)
    return res.status(400).json({ error: 'Not enough credits' });

  db.prepare('UPDATE players SET credits = credits - ? WHERE id = ?').run(cosmetic.price, req.player.id);
  db.prepare('INSERT INTO player_cosmetics (player_id, cosmetic_id) VALUES (?,?)').run(req.player.id, cosmetic_id);

  const updated = db.prepare('SELECT credits FROM players WHERE id = ?').get(req.player.id);
  res.json({ success: true, credits: updated.credits });
});

// POST /cosmetics/equip
app.post('/cosmetics/equip', requireAuth, (req, res) => {
  const { cosmetic_id, equipped } = req.body;
  if (!cosmetic_id) return res.status(400).json({ error: 'cosmetic_id required' });
  const owned = db.prepare('SELECT 1 FROM player_cosmetics WHERE player_id = ? AND cosmetic_id = ?').get(req.player.id, cosmetic_id);
  if (!owned) return res.status(403).json({ error: 'Cosmetic not owned' });
  db.prepare('UPDATE player_cosmetics SET equipped = ? WHERE player_id = ? AND cosmetic_id = ?').run(equipped ? 1 : 0, req.player.id, cosmetic_id);
  res.json({ success: true });
});

// ── Broadcast Routes ─────────────────────────────────────────────────────────

// GET /broadcasts  — get active messages for a game
app.get('/broadcasts', (req, res) => {
  const { game_id } = req.query;
  const msgs = db.prepare('SELECT * FROM broadcast_messages WHERE game_id = ? OR game_id IS NULL ORDER BY created_at DESC LIMIT 10').all(game_id || null);
  res.json({ success: true, messages: msgs });
});

// ── Leaderboard ──────────────────────────────────────────────────────────────

// GET /leaderboard?game_id=xxx&stat=score&limit=10
app.get('/leaderboard', (req, res) => {
  const { game_id, stat = 'score', limit = 10 } = req.query;
  if (!game_id) return res.status(400).json({ error: 'game_id required' });

  const rows = db.prepare(`
    SELECT p.username, pd.value, p.id as player_id
    FROM player_data pd
    JOIN players p ON p.id = pd.player_id
    WHERE p.game_id = ? AND pd.key = ? AND p.banned = 0
    ORDER BY CAST(pd.value AS REAL) DESC
    LIMIT ?
  `).all(game_id, stat, parseInt(limit));

  const board = rows.map((r, i) => ({
    rank: i + 1,
    username: r.username,
    value: JSON.parse(r.value),
    player_id: r.player_id
  }));

  res.json({ success: true, leaderboard: board });
});

// ── Owner Routes ─────────────────────────────────────────────────────────────

// POST /owner/verify
app.post('/owner/verify', (req, res) => {
  const { password } = req.body;
  if (password === OWNER_PASSWORD) {
    res.json({ success: true });
  } else {
    res.status(403).json({ error: 'Wrong password' });
  }
});

// GET /owner/players
app.get('/owner/players', requireOwner, (req, res) => {
  const { game_id } = req.query;
  let rows;
  if (game_id) {
    rows = db.prepare('SELECT id, game_id, username, credits, banned, created_at FROM players WHERE game_id = ? ORDER BY created_at DESC').all(game_id);
  } else {
    rows = db.prepare('SELECT id, game_id, username, credits, banned, created_at FROM players ORDER BY created_at DESC').all();
  }
  res.json({ success: true, players: rows });
});

// GET /owner/games  — list all unique game IDs
app.get('/owner/games', requireOwner, (req, res) => {
  const rows = db.prepare('SELECT game_id, COUNT(*) as player_count FROM players GROUP BY game_id').all();
  res.json({ success: true, games: rows });
});

// POST /owner/credits/give
app.post('/owner/credits/give', requireOwner, (req, res) => {
  const { player_id, amount } = req.body;
  if (!player_id || !amount) return res.status(400).json({ error: 'player_id and amount required' });
  const result = db.prepare('UPDATE players SET credits = credits + ? WHERE id = ?').run(amount, player_id);
  if (!result.changes) return res.status(404).json({ error: 'Player not found' });
  const p = db.prepare('SELECT credits FROM players WHERE id = ?').get(player_id);
  res.json({ success: true, new_credits: p.credits });
});

// POST /owner/credits/set
app.post('/owner/credits/set', requireOwner, (req, res) => {
  const { player_id, amount } = req.body;
  if (!player_id || amount === undefined) return res.status(400).json({ error: 'player_id and amount required' });
  const result = db.prepare('UPDATE players SET credits = ? WHERE id = ?').run(amount, player_id);
  if (!result.changes) return res.status(404).json({ error: 'Player not found' });
  res.json({ success: true, credits: amount });
});

// POST /owner/ban
app.post('/owner/ban', requireOwner, (req, res) => {
  const { player_id, banned = 1 } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id required' });
  db.prepare('UPDATE players SET banned = ? WHERE id = ?').run(banned ? 1 : 0, player_id);
  res.json({ success: true, banned: !!banned });
});

// DELETE /owner/player/:id
app.delete('/owner/player/:id', requireOwner, (req, res) => {
  const id = req.params.id;
  db.prepare('DELETE FROM player_data WHERE player_id = ?').run(id);
  db.prepare('DELETE FROM player_cosmetics WHERE player_id = ?').run(id);
  db.prepare('DELETE FROM inventory WHERE player_id = ?').run(id);
  db.prepare('DELETE FROM players WHERE id = ?').run(id);
  res.json({ success: true });
});

// POST /owner/cosmetics/create
app.post('/owner/cosmetics/create', requireOwner, (req, res) => {
  const { game_id, name, type, description, price = 0, rarity = 'common' } = req.body;
  if (!game_id || !name || !type) return res.status(400).json({ error: 'game_id, name, and type required' });
  const id = uuidv4();
  db.prepare('INSERT INTO cosmetics_catalog (id, game_id, name, type, description, price, rarity) VALUES (?,?,?,?,?,?,?)')
    .run(id, game_id, name, type, description, price, rarity);
  res.json({ success: true, cosmetic_id: id });
});

// DELETE /owner/cosmetics/:id
app.delete('/owner/cosmetics/:id', requireOwner, (req, res) => {
  db.prepare('DELETE FROM player_cosmetics WHERE cosmetic_id = ?').run(req.params.id);
  db.prepare('DELETE FROM cosmetics_catalog WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// POST /owner/cosmetics/grant  — give cosmetic to player for free
app.post('/owner/cosmetics/grant', requireOwner, (req, res) => {
  const { player_id, cosmetic_id } = req.body;
  if (!player_id || !cosmetic_id) return res.status(400).json({ error: 'player_id and cosmetic_id required' });
  try {
    db.prepare('INSERT OR IGNORE INTO player_cosmetics (player_id, cosmetic_id) VALUES (?,?)').run(player_id, cosmetic_id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /owner/inventory/give
app.post('/owner/inventory/give', requireOwner, (req, res) => {
  const { player_id, item_name, quantity = 1 } = req.body;
  if (!player_id || !item_name) return res.status(400).json({ error: 'player_id and item_name required' });
  db.prepare(`
    INSERT INTO inventory (player_id, item_name, quantity)
    VALUES (?,?,?)
    ON CONFLICT(player_id, item_name) DO UPDATE SET quantity = quantity + excluded.quantity
  `).run(player_id, item_name, quantity);
  res.json({ success: true });
});

// POST /owner/broadcast
app.post('/owner/broadcast', requireOwner, (req, res) => {
  const { message, game_id } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });
  const id = uuidv4();
  db.prepare('INSERT INTO broadcast_messages (id, game_id, message) VALUES (?,?,?)').run(id, game_id || null, message);
  res.json({ success: true, broadcast_id: id });
});

// DELETE /owner/broadcast/:id
app.delete('/owner/broadcast/:id', requireOwner, (req, res) => {
  db.prepare('DELETE FROM broadcast_messages WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// GET /owner/stats
app.get('/owner/stats', requireOwner, (req, res) => {
  const total_players = db.prepare('SELECT COUNT(*) as c FROM players').get().c;
  const total_games = db.prepare('SELECT COUNT(DISTINCT game_id) as c FROM players').get().c;
  const total_credits = db.prepare('SELECT SUM(credits) as c FROM players').get().c || 0;
  const banned_players = db.prepare('SELECT COUNT(*) as c FROM players WHERE banned = 1').get().c;
  const total_cosmetics = db.prepare('SELECT COUNT(*) as c FROM cosmetics_catalog').get().c;
  res.json({ success: true, stats: { total_players, total_games, total_credits, banned_players, total_cosmetics } });
});

// ── Serve Dashboard ───────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🎮 Game Backend running on port ${PORT}`);
  console.log(`🔑 Owner password: ${OWNER_PASSWORD}`);
  console.log(`   Set OWNER_PASSWORD env var to change this!`);
});
