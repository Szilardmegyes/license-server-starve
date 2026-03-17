// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();
app.use(express.json());

// --- Config from env ---
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "password";
const ADMIN_KEY = process.env.ADMIN_KEY || "adminkey";
const PORT = process.env.PORT || 3000;
const KEY_FILE = path.join(__dirname, "keys.json");

// --- CORS (allow all origins so Tampermonkey clients can call) ---
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-key");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// --- Load or init keys ---
let keys = {};
try {
  if (fs.existsSync(KEY_FILE)) {
    keys = JSON.parse(fs.readFileSync(KEY_FILE, "utf8"));
  } else {
    keys = {}; // empty
    fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
  }
} catch (e) {
  console.error("Failed to load keys.json:", e);
  keys = {};
}

function saveKeys() {
  try {
    fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
  } catch (e) {
    console.error("Failed to save keys.json:", e);
  }
}

function nowISO() {
  return new Date().toISOString();
}

function makeKeyString(len = 8) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let k = "";
  for (let i = 0; i < len; i++) k += chars.charAt(Math.floor(Math.random() * chars.length));
  return k;
}

function generateId() {
  return "id-" + Date.now().toString(36) + "-" + Math.floor(Math.random() * 1e6).toString(36);
}

// Ensure key unique
function genUniqueKey(len = 8) {
  let tries = 0;
  while (tries++ < 1000) {
    const k = makeKeyString(len);
    if (!keys[k]) return k;
  }
  throw new Error("Unable to generate unique key");
}

// --- Admin auth middleware helper ---
// Checks either Authorization Basic or x-admin-key header
function isAdminAuthorized(req) {
  const adminKeyHeader = req.header("x-admin-key");
  if (adminKeyHeader && adminKeyHeader === ADMIN_KEY) return true;

  const auth = req.header("authorization");
  if (!auth || !auth.startsWith("Basic ")) return false;
  try {
    const b = Buffer.from(auth.slice(6), "base64").toString("utf8");
    const [user, pass] = b.split(":");
    if (user === ADMIN_USER && pass === ADMIN_PASS) return true;
  } catch (e) { }
  return false;
}

function requireAdmin(req, res, next) {
  if (isAdminAuthorized(req)) return next();
  res.status(401).json({ error: "unauthorized" });
}

// --- Public test route ---
app.get("/", (req, res) => {
  res.send("License server running");
});

// --- API: check key (client calls this on login) ---
app.post("/api/check", (req, res) => {
  const { key, clientId, hw } = req.body || {};
  if (!key) return res.json({ valid: false, reason: "missing_key" });

  const record = keys[key];
  if (!record) return res.json({ valid: false, reason: "invalid_key" });

  // If not active, lock to this clientId
  if (!record.active) {
    record.active = true;
    record.clientId = clientId || null;
    record.hw = hw || null;
    record.lastSeen = nowISO();
    record.activatedAt = nowISO();
    saveKeys();
    return res.json({ valid: true });
  }

  // If already active, allow if same clientId
  if (record.clientId && clientId && record.clientId === clientId) {
    record.lastSeen = nowISO();
    saveKeys();
    return res.json({ valid: true });
  }

  // otherwise in use
  return res.json({ valid: false, reason: "key_in_use" });
});

// --- API: heartbeat (clients should call periodically) ---
app.post("/api/heartbeat", (req, res) => {
  const { key, clientId, hw } = req.body || {};
  if (!key) return res.json({ valid: false });
  const record = keys[key];
  if (!record) return res.json({ valid: false });
  if (record.clientId && clientId && record.clientId === clientId) {
    record.lastSeen = nowISO();
    if (hw) record.hw = hw;
    saveKeys();
    return res.json({ valid: true });
  }
  return res.json({ valid: false });
});

// --- API: release (client calls on beforeunload) ---
app.post("/api/release", (req, res) => {
  const { key, clientId } = req.body || {};
  if (!key) return res.json({});
  const record = keys[key];
  if (!record) return res.json({});
  if (record.clientId && clientId && record.clientId === clientId) {
    record.active = false;
    record.clientId = null;
    record.hw = null;
    record.lastSeen = null;
    record.activatedAt = null;
    saveKeys();
  }
  res.json({});
});

// --- Admin API: list all keys ---
app.get("/api/admin/list", requireAdmin, (req, res) => {
  const out = [];
  for (const key in keys) {
    const r = Object.assign({ key }, keys[key]);
    out.push(r);
  }
  res.json({ keys: out });
});

// --- Admin API: generate count keys ---
app.post("/api/admin/generate", requireAdmin, (req, res) => {
  let count = parseInt(req.body && req.body.count, 10) || 1;
  count = Math.max(1, Math.min(500, count)); // safety cap
  const created = [];
  for (let i = 0; i < count; i++) {
    const id = generateId();
    const key = genUniqueKey(8);
    keys[key] = {
      id,
      active: false,
      clientId: null,
      hw: null,
      createdAt: nowISO(),
      activatedAt: null,
      lastSeen: null
    };
    created.push({ key, id });
  }
  saveKeys();
  res.json({ generated: created });
});

// --- Admin API: delete key by id ---
app.post("/api/admin/delete", requireAdmin, (req, res) => {
  const id = req.body && req.body.id;
  if (!id) return res.json({ success: false, reason: "missing_id" });
  for (const k in keys) {
    if (keys[k].id === id) {
      delete keys[k];
      saveKeys();
      return res.json({ success: true });
    }
  }
  res.json({ success: false, reason: "not_found" });
});

// --- Admin API: delete all keys (danger) ---
app.post("/api/admin/delete-all", requireAdmin, (req, res) => {
  keys = {};
  saveKeys();
  res.json({ success: true });
});

// --- Admin API: stats ---
app.get("/api/admin/stats", requireAdmin, (req, res) => {
  let total = 0, active = 0, inactive = 0;
  const activeList = [];
  for (const k in keys) {
    total++;
    if (keys[k].active) {
      active++;
      activeList.push({
        key: k,
        id: keys[k].id,
        clientId: keys[k].clientId,
        hw: keys[k].hw,
        activatedAt: keys[k].activatedAt,
        lastSeen: keys[k].lastSeen
      });
    } else inactive++;
  }
  res.json({ total, active, inactive, activeList });
});

// --- Serve admin HTML + static (we'll embed a single-file admin page) ---
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Optionally serve keys.json for debugging (admin only)
app.get("/api/admin/keys.json", requireAdmin, (req, res) => {
  res.sendFile(KEY_FILE);
});

app.listen(PORT, () => {
  console.log("License server running on port", PORT);
});
