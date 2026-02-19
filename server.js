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

app.get('/me', requireAuth, (req, res) => {
  const { id, game_id, username, credits, created_at } = req.player;
  res.json({ player_id: id, game_id, username, credits, created_at });
});

// ── Save Data Routes ─────────────────────────────────────────────────────────

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

app.get('/load', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM player_data WHERE player_id = ?').all(req.player.id);
  const data = {};
  for (const row of rows) {
    try { data[row.key] = JSON.parse(row.value); } catch { data[row.key] = row.value; }
  }
  res.json({ success: true, data });
});

app.delete('/save/:key', requireAuth, (req, res) => {
  db.prepare('DELETE FROM player_data WHERE player_id = ? AND key = ?').run(req.player.id, req.params.key);
  res.json({ success: true });
});

// ── Credits Routes ───────────────────────────────────────────────────────────

app.get('/credits', requireAuth, (req, res) => {
  res.json({ success: true, credits: req.player.credits });
});

app.post('/credits/spend', requireAuth, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  if (req.player.credits < amount) return res.status(400).json({ error: 'Not enough credits' });
  db.prepare('UPDATE players SET credits = credits - ? WHERE id = ?').run(amount, req.player.id);
  const updated = db.prepare('SELECT credits FROM players WHERE id = ?').get(req.player.id);
  res.json({ success: true, credits: updated.credits });
});

app.post('/credits/add', requireAuth, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  db.prepare('UPDATE players SET credits = credits + ? WHERE id = ?').run(amount, req.player.id);
  const updated = db.prepare('SELECT credits FROM players WHERE id = ?').get(req.player.id);
  res.json({ success: true, credits: updated.credits });
});

// ── Inventory Routes ─────────────────────────────────────────────────────────

app.get('/inventory', requireAuth, (req, res) => {
  const items = db.prepare('SELECT item_name, quantity, metadata FROM inventory WHERE player_id = ?').all(req.player.id);
  res.json({ success: true, inventory: items });
});

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

app.get('/cosmetics/catalog', (req, res) => {
  const { game_id } = req.query;
  if (!game_id) return res.status(400).json({ error: 'game_id query param required' });
  const items = db.prepare('SELECT * FROM cosmetics_catalog WHERE game_id = ?').all(game_id);
  res.json({ success: true, cosmetics: items });
});

app.get('/cosmetics/owned', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*, pc.equipped, pc.obtained_at
    FROM player_cosmetics pc
    JOIN cosmetics_catalog c ON c.id = pc.cosmetic_id
    WHERE pc.player_id = ?
  `).all(req.player.id);
  res.json({ success: true, cosmetics: rows });
});

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

app.post('/cosmetics/equip', requireAuth, (req, res) => {
  const { cosmetic_id, equipped } = req.body;
  if (!cosmetic_id) return res.status(400).json({ error: 'cosmetic_id required' });
  const owned = db.prepare('SELECT 1 FROM player_cosmetics WHERE player_id = ? AND cosmetic_id = ?').get(req.player.id, cosmetic_id);
  if (!owned) return res.status(403).json({ error: 'Cosmetic not owned' });
  db.prepare('UPDATE player_cosmetics SET equipped = ? WHERE player_id = ? AND cosmetic_id = ?').run(equipped ? 1 : 0, req.player.id, cosmetic_id);
  res.json({ success: true });
});

// ── Broadcast Routes ─────────────────────────────────────────────────────────

app.get('/broadcasts', (req, res) => {
  const { game_id } = req.query;
  const msgs = db.prepare('SELECT * FROM broadcast_messages WHERE game_id = ? OR game_id IS NULL ORDER BY created_at DESC LIMIT 10').all(game_id || null);
  res.json({ success: true, messages: msgs });
});

// ── Leaderboard ──────────────────────────────────────────────────────────────

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

app.post('/owner/verify', (req, res) => {
  const { password } = req.body;
  if (password === OWNER_PASSWORD) {
    res.json({ success: true });
  } else {
    res.status(403).json({ error: 'Wrong password' });
  }
});

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

app.get('/owner/games', requireOwner, (req, res) => {
  const rows = db.prepare('SELECT game_id, COUNT(*) as player_count FROM players GROUP BY game_id').all();
  res.json({ success: true, games: rows });
});

app.post('/owner/credits/give', requireOwner, (req, res) => {
  const { player_id, amount } = req.body;
  if (!player_id || !amount) return res.status(400).json({ error: 'player_id and amount required' });
  const result = db.prepare('UPDATE players SET credits = credits + ? WHERE id = ?').run(amount, player_id);
  if (!result.changes) return res.status(404).json({ error: 'Player not found' });
  const p = db.prepare('SELECT credits FROM players WHERE id = ?').get(player_id);
  res.json({ success: true, new_credits: p.credits });
});

app.post('/owner/credits/set', requireOwner, (req, res) => {
  const { player_id, amount } = req.body;
  if (!player_id || amount === undefined) return res.status(400).json({ error: 'player_id and amount required' });
  const result = db.prepare('UPDATE players SET credits = ? WHERE id = ?').run(amount, player_id);
  if (!result.changes) return res.status(404).json({ error: 'Player not found' });
  res.json({ success: true, credits: amount });
});

app.post('/owner/ban', requireOwner, (req, res) => {
  const { player_id, banned = 1 } = req.body;
  if (!player_id) return res.status(400).json({ error: 'player_id required' });
  db.prepare('UPDATE players SET banned = ? WHERE id = ?').run(banned ? 1 : 0, player_id);
  res.json({ success: true, banned: !!banned });
});

app.delete('/owner/player/:id', requireOwner, (req, res) => {
  const id = req.params.id;
  db.prepare('DELETE FROM player_data WHERE player_id = ?').run(id);
  db.prepare('DELETE FROM player_cosmetics WHERE player_id = ?').run(id);
  db.prepare('DELETE FROM inventory WHERE player_id = ?').run(id);
  db.prepare('DELETE FROM players WHERE id = ?').run(id);
  res.json({ success: true });
});

app.post('/owner/cosmetics/create', requireOwner, (req, res) => {
  const { game_id, name, type, description, price = 0, rarity = 'common' } = req.body;
  if (!game_id || !name || !type) return res.status(400).json({ error: 'game_id, name, and type required' });
  const id = uuidv4();
  db.prepare('INSERT INTO cosmetics_catalog (id, game_id, name, type, description, price, rarity) VALUES (?,?,?,?,?,?,?)')
    .run(id, game_id, name, type, description, price, rarity);
  res.json({ success: true, cosmetic_id: id });
});

app.delete('/owner/cosmetics/:id', requireOwner, (req, res) => {
  db.prepare('DELETE FROM player_cosmetics WHERE cosmetic_id = ?').run(req.params.id);
  db.prepare('DELETE FROM cosmetics_catalog WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

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

app.post('/owner/broadcast', requireOwner, (req, res) => {
  const { message, game_id } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });
  const id = uuidv4();
  db.prepare('INSERT INTO broadcast_messages (id, game_id, message) VALUES (?,?,?)').run(id, game_id || null, message);
  res.json({ success: true, broadcast_id: id });
});

app.delete('/owner/broadcast/:id', requireOwner, (req, res) => {
  db.prepare('DELETE FROM broadcast_messages WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/owner/stats', requireOwner, (req, res) => {
  const total_players = db.prepare('SELECT COUNT(*) as c FROM players').get().c;
  const total_games = db.prepare('SELECT COUNT(DISTINCT game_id) as c FROM players').get().c;
  const total_credits = db.prepare('SELECT SUM(credits) as c FROM players').get().c || 0;
  const banned_players = db.prepare('SELECT COUNT(*) as c FROM players WHERE banned = 1').get().c;
  const total_cosmetics = db.prepare('SELECT COUNT(*) as c FROM cosmetics_catalog').get().c;
  res.json({ success: true, stats: { total_players, total_games, total_credits, banned_players, total_cosmetics } });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ════════════════════════════════════════════════════════════════════════════
// NEW ADDITIONS — everything below is new; nothing above was changed
// ════════════════════════════════════════════════════════════════════════════

// ── Ensure new tables exist ───────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS game_config (
    game_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (game_id, key)
  );

  CREATE TABLE IF NOT EXISTS player_notes (
    id TEXT PRIMARY KEY,
    player_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_by TEXT DEFAULT 'owner',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS friend_relationships (
    player_id TEXT NOT NULL,
    friend_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (player_id, friend_id)
  );
`);

// ── Game Config routes ────────────────────────────────────────────────────────

// GET /config?game_id=xxx  — public: get all config for a game
app.get('/config', (req, res) => {
  const { game_id } = req.query;
  if (!game_id) return res.status(400).json({ error: 'game_id required' });
  const rows = db.prepare('SELECT key, value FROM game_config WHERE game_id = ?').all(game_id);
  const config = {};
  for (const r of rows) {
    try { config[r.key] = JSON.parse(r.value); } catch { config[r.key] = r.value; }
  }
  res.json({ success: true, config });
});

// GET /config/:key?game_id=xxx  — public: get a single config value
app.get('/config/:key', (req, res) => {
  const { game_id } = req.query;
  if (!game_id) return res.status(400).json({ error: 'game_id required' });
  const row = db.prepare('SELECT value FROM game_config WHERE game_id = ? AND key = ?').get(game_id, req.params.key);
  if (!row) return res.status(404).json({ error: 'Key not found' });
  let value;
  try { value = JSON.parse(row.value); } catch { value = row.value; }
  res.json({ success: true, key: req.params.key, value });
});

// POST /owner/config/set  — owner: set a config key
app.post('/owner/config/set', requireOwner, (req, res) => {
  const { game_id, key, value } = req.body;
  if (!game_id || !key || value === undefined)
    return res.status(400).json({ error: 'game_id, key, and value required' });
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  db.prepare(`
    INSERT INTO game_config (game_id, key, value, updated_at)
    VALUES (?,?,?,datetime('now'))
    ON CONFLICT(game_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(game_id, key, serialized);
  res.json({ success: true });
});

// DELETE /owner/config/:game_id/:key  — owner: delete a config key
app.delete('/owner/config/:game_id/:key', requireOwner, (req, res) => {
  db.prepare('DELETE FROM game_config WHERE game_id = ? AND key = ?').run(req.params.game_id, req.params.key);
  res.json({ success: true });
});

// GET /owner/config/:game_id  — owner: list all config for a game
app.get('/owner/config/:game_id', requireOwner, (req, res) => {
  const rows = db.prepare('SELECT key, value, updated_at FROM game_config WHERE game_id = ?').all(req.params.game_id);
  const config = {};
  for (const r of rows) {
    try { config[r.key] = JSON.parse(r.value); } catch { config[r.key] = r.value; }
  }
  res.json({ success: true, config });
});

// ── Player Notes routes (owner only) ─────────────────────────────────────────

// GET /owner/notes/:player_id  — get all notes for a player
app.get('/owner/notes/:player_id', requireOwner, (req, res) => {
  const notes = db.prepare('SELECT * FROM player_notes WHERE player_id = ? ORDER BY created_at DESC').all(req.params.player_id);
  res.json({ success: true, notes });
});

// POST /owner/notes  — add a note to a player
app.post('/owner/notes', requireOwner, (req, res) => {
  const { player_id, note } = req.body;
  if (!player_id || !note) return res.status(400).json({ error: 'player_id and note required' });
  const id = uuidv4();
  db.prepare('INSERT INTO player_notes (id, player_id, note) VALUES (?,?,?)').run(id, player_id, note);
  res.json({ success: true, note_id: id });
});

// DELETE /owner/notes/:note_id  — delete a note
app.delete('/owner/notes/:note_id', requireOwner, (req, res) => {
  db.prepare('DELETE FROM player_notes WHERE id = ?').run(req.params.note_id);
  res.json({ success: true });
});

// ── Enhanced Owner Stats ──────────────────────────────────────────────────────

// GET /owner/stats/game/:game_id  — per-game detailed stats
app.get('/owner/stats/game/:game_id', requireOwner, (req, res) => {
  const gid = req.params.game_id;
  const total = db.prepare('SELECT COUNT(*) as c FROM players WHERE game_id = ?').get(gid).c;
  const banned = db.prepare('SELECT COUNT(*) as c FROM players WHERE game_id = ? AND banned = 1').get(gid).c;
  const total_credits = db.prepare('SELECT SUM(credits) as c FROM players WHERE game_id = ?').get(gid).c || 0;
  const avg_credits = total > 0 ? Math.round(total_credits / total) : 0;
  const top_player = db.prepare('SELECT username, credits FROM players WHERE game_id = ? ORDER BY credits DESC LIMIT 1').get(gid);
  const newest = db.prepare('SELECT username, created_at FROM players WHERE game_id = ? ORDER BY created_at DESC LIMIT 1').get(gid);
  const cosmetic_count = db.prepare('SELECT COUNT(*) as c FROM cosmetics_catalog WHERE game_id = ?').get(gid).c;
  res.json({
    success: true,
    game_id: gid,
    stats: { total, banned, total_credits, avg_credits, top_player, newest, cosmetic_count }
  });
});

// ── Bulk Owner Operations ─────────────────────────────────────────────────────

// POST /owner/bulk/ban  — ban or unban multiple players
app.post('/owner/bulk/ban', requireOwner, (req, res) => {
  const { player_ids, banned = true } = req.body;
  if (!Array.isArray(player_ids) || !player_ids.length)
    return res.status(400).json({ error: 'player_ids array required' });
  const stmt = db.prepare('UPDATE players SET banned = ? WHERE id = ?');
  const tx = db.transaction((ids) => { for (const id of ids) stmt.run(banned ? 1 : 0, id); });
  tx(player_ids);
  res.json({ success: true, updated: player_ids.length });
});

// POST /owner/bulk/credits  — give credits to multiple players
app.post('/owner/bulk/credits', requireOwner, (req, res) => {
  const { player_ids, amount } = req.body;
  if (!Array.isArray(player_ids) || !player_ids.length || !amount)
    return res.status(400).json({ error: 'player_ids array and amount required' });
  const stmt = db.prepare('UPDATE players SET credits = credits + ? WHERE id = ?');
  const tx = db.transaction((ids) => { for (const id of ids) stmt.run(amount, id); });
  tx(player_ids);
  res.json({ success: true, updated: player_ids.length });
});

// POST /owner/bulk/delete  — delete multiple players
app.post('/owner/bulk/delete', requireOwner, (req, res) => {
  const { player_ids } = req.body;
  if (!Array.isArray(player_ids) || !player_ids.length)
    return res.status(400).json({ error: 'player_ids array required' });
  const tx = db.transaction((ids) => {
    for (const id of ids) {
      db.prepare('DELETE FROM player_data WHERE player_id = ?').run(id);
      db.prepare('DELETE FROM player_cosmetics WHERE player_id = ?').run(id);
      db.prepare('DELETE FROM inventory WHERE player_id = ?').run(id);
      db.prepare('DELETE FROM players WHERE id = ?').run(id);
    }
  });
  tx(player_ids);
  res.json({ success: true, deleted: player_ids.length });
});

// ── Credits Leaderboard ───────────────────────────────────────────────────────

// GET /leaderboard/credits?game_id=xxx&limit=10
app.get('/leaderboard/credits', (req, res) => {
  const { game_id, limit = 10 } = req.query;
  if (!game_id) return res.status(400).json({ error: 'game_id required' });
  const rows = db.prepare('SELECT id as player_id, username, credits FROM players WHERE game_id = ? AND banned = 0 ORDER BY credits DESC LIMIT ?').all(game_id, parseInt(limit));
  const board = rows.map((r, i) => ({ rank: i + 1, ...r }));
  res.json({ success: true, leaderboard: board });
});

// ── Password Reset Tokens ─────────────────────────────────────────────────────

// POST /owner/reset-password  — owner resets a player's password
app.post('/owner/reset-password', requireOwner, (req, res) => {
  const { player_id, new_password } = req.body;
  if (!player_id || !new_password)
    return res.status(400).json({ error: 'player_id and new_password required' });
  const player = db.prepare('SELECT id FROM players WHERE id = ?').get(player_id);
  if (!player) return res.status(404).json({ error: 'Player not found' });
  const hash = bcrypt.hashSync(new_password, 10);
  const token = uuidv4(); // also invalidate old token
  db.prepare('UPDATE players SET password_hash = ?, token = ? WHERE id = ?').run(hash, token, player_id);
  res.json({ success: true });
});

// ── Player Search ─────────────────────────────────────────────────────────────

// GET /owner/search?q=name&game_id=xxx
app.get('/owner/search', requireOwner, (req, res) => {
  const { q, game_id } = req.query;
  if (!q) return res.status(400).json({ error: 'q query param required' });
  const like = `%${q}%`;
  let rows;
  if (game_id) {
    rows = db.prepare('SELECT id, game_id, username, credits, banned, created_at FROM players WHERE game_id = ? AND username LIKE ? LIMIT 20').all(game_id, like);
  } else {
    rows = db.prepare('SELECT id, game_id, username, credits, banned, created_at FROM players WHERE username LIKE ? LIMIT 20').all(like);
  }
  res.json({ success: true, players: rows });
});

// ── Player Inventory (owner view) ────────────────────────────────────────────

// GET /owner/inventory/:player_id
app.get('/owner/inventory/:player_id', requireOwner, (req, res) => {
  const items = db.prepare('SELECT item_name, quantity, metadata FROM inventory WHERE player_id = ?').all(req.params.player_id);
  res.json({ success: true, inventory: items });
});

// GET /owner/save/:player_id  — view a player's save data
app.get('/owner/save/:player_id', requireOwner, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM player_data WHERE player_id = ?').all(req.params.player_id);
  const data = {};
  for (const row of rows) {
    try { data[row.key] = JSON.parse(row.value); } catch { data[row.key] = row.value; }
  }
  res.json({ success: true, data });
});

// ── Friends / Social ──────────────────────────────────────────────────────────

// POST /friends/request  — send a friend request
app.post('/friends/request', requireAuth, (req, res) => {
  const { friend_username } = req.body;
  if (!friend_username) return res.status(400).json({ error: 'friend_username required' });
  const friend = db.prepare('SELECT id FROM players WHERE game_id = ? AND username = ?').get(req.player.game_id, friend_username);
  if (!friend) return res.status(404).json({ error: 'Player not found in this game' });
  if (friend.id === req.player.id) return res.status(400).json({ error: 'Cannot add yourself' });
  try {
    db.prepare('INSERT OR IGNORE INTO friend_relationships (player_id, friend_id, status) VALUES (?,?,?)').run(req.player.id, friend.id, 'pending');
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /friends/accept  — accept a friend request
app.post('/friends/accept', requireAuth, (req, res) => {
  const { friend_id } = req.body;
  if (!friend_id) return res.status(400).json({ error: 'friend_id required' });
  db.prepare("UPDATE friend_relationships SET status = 'accepted' WHERE player_id = ? AND friend_id = ?").run(friend_id, req.player.id);
  db.prepare("INSERT OR IGNORE INTO friend_relationships (player_id, friend_id, status) VALUES (?,?,'accepted')").run(req.player.id, friend_id);
  res.json({ success: true });
});

// GET /friends  — get accepted friends list
app.get('/friends', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT p.id, p.username, p.credits
    FROM friend_relationships fr
    JOIN players p ON p.id = fr.friend_id
    WHERE fr.player_id = ? AND fr.status = 'accepted'
  `).all(req.player.id);
  res.json({ success: true, friends: rows });
});

// ── Health & Info ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as c FROM players').get().c;
  const games = db.prepare('SELECT COUNT(DISTINCT game_id) as c FROM players').get().c;
  res.json({ status: 'ok', players: total, games, uptime: process.uptime() });
});

app.listen(PORT, () => {
  console.log(`🎮 Game Backend running on port ${PORT}`);
  console.log(`🔑 Owner password: ${OWNER_PASSWORD}`);
  console.log(`   Set OWNER_PASSWORD env var to change this!`);
});
