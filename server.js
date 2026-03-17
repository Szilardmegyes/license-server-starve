const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "password";
const ADMIN_KEY = process.env.ADMIN_KEY || "adminkey";
const PORT = process.env.PORT || 3000;

const KEY_FILE = path.join(__dirname, "keys.json");
const SESSION_TTL_MS = 70 * 1000;

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-key");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});

let keys = {};
try {
    if (fs.existsSync(KEY_FILE)) {
        keys = JSON.parse(fs.readFileSync(KEY_FILE, "utf8"));
    } else {
        keys = {};
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

function nowMs() {
    return Date.now();
}

function makeKeyString(len = 8) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let k = "";
    for (let i = 0; i < len; i++) {
        k += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return k;
}

function generateId() {
    return "id-" + Date.now().toString(36) + "-" + Math.floor(Math.random() * 1e6).toString(36);
}

function genUniqueKey(len = 8) {
    let tries = 0;
    while (tries++ < 1000) {
        const k = makeKeyString(len);
        if (!keys[k]) return k;
    }
    throw new Error("Unable to generate unique key");
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString("hex");
}

function isSessionExpired(record) {
    if (!record.session || !record.session.expiresAt) return true;
    return nowMs() > record.session.expiresAt;
}

function clearSession(record) {
    record.active = false;
    record.clientId = null;
    record.hw = null;
    record.activatedAt = null;
    record.lastSeen = null;
    record.session = null;
}

function normalizeRecord(record) {
    if (!record.session) record.session = null;
    if (record.active && record.session && isSessionExpired(record)) {
        clearSession(record);
    }
}

function isAdminAuthorized(req) {
    const adminKeyHeader = req.header("x-admin-key");
    if (adminKeyHeader && adminKeyHeader === ADMIN_KEY) return true;

    const auth = req.header("authorization");
    if (!auth || !auth.startsWith("Basic ")) return false;

    try {
        const b = Buffer.from(auth.slice(6), "base64").toString("utf8");
        const [user, pass] = b.split(":");
        if (user === ADMIN_USER && pass === ADMIN_PASS) return true;
    } catch (e) {}

    return false;
}

function requireAdmin(req, res, next) {
    if (isAdminAuthorized(req)) return next();
    res.status(401).json({ error: "unauthorized" });
}

app.get("/", (req, res) => {
    res.send("License server running");
});

app.post("/api/check", (req, res) => {
    const { key, clientId, hw } = req.body || {};

    if (!key) {
        return res.json({ valid: false, error: "missing_key" });
    }

    const record = keys[key];
    if (!record) {
        return res.json({ valid: false, error: "invalid_key" });
    }

    normalizeRecord(record);

    if (record.active && record.clientId && clientId && record.clientId !== clientId) {
        return res.json({ valid: false, error: "key_in_use" });
    }

    const sessionToken = generateSessionToken();
    const expiresAt = nowMs() + SESSION_TTL_MS;

    record.active = true;
    record.clientId = clientId || null;
    record.hw = hw || null;
    record.activatedAt = record.activatedAt || nowISO();
    record.lastSeen = nowISO();
    record.session = {
        token: sessionToken,
        expiresAt
    };

    saveKeys();

    return res.json({
        valid: true,
        sessionToken,
        expiresIn: Math.floor(SESSION_TTL_MS / 1000)
    });
});

app.post("/api/heartbeat", (req, res) => {
    const { sessionToken, clientId, hw } = req.body || {};

    if (!sessionToken) {
        return res.json({ valid: false, error: "missing_session" });
    }

    let matchedKey = null;
    let matchedRecord = null;

    for (const key in keys) {
        const record = keys[key];
        normalizeRecord(record);

        if (record.session && record.session.token === sessionToken) {
            matchedKey = key;
            matchedRecord = record;
            break;
        }
    }

    if (!matchedRecord) {
        return res.json({ valid: false, error: "invalid_session" });
    }

    if (matchedRecord.clientId && clientId && matchedRecord.clientId !== clientId) {
        return res.json({ valid: false, error: "client_mismatch" });
    }

    matchedRecord.lastSeen = nowISO();
    if (hw) matchedRecord.hw = hw;
    matchedRecord.session.expiresAt = nowMs() + SESSION_TTL_MS;

    saveKeys();

    return res.json({
        valid: true,
        key: matchedKey,
        expiresIn: Math.floor(SESSION_TTL_MS / 1000)
    });
});

app.post("/api/release", (req, res) => {
    const { sessionToken, clientId } = req.body || {};

    if (!sessionToken) {
        return res.json({ ok: true });
    }

    for (const key in keys) {
        const record = keys[key];
        if (!record.session) continue;

        if (record.session.token === sessionToken) {
            if (!record.clientId || !clientId || record.clientId === clientId) {
                clearSession(record);
                saveKeys();
            }
            break;
        }
    }

    res.json({ ok: true });
});

app.get("/api/admin/list", requireAdmin, (req, res) => {
    const out = [];
    for (const key in keys) {
        normalizeRecord(keys[key]);
        out.push({ key, ...keys[key] });
    }
    saveKeys();
    res.json({ keys: out });
});

app.post("/api/admin/generate", requireAdmin, (req, res) => {
    let count = parseInt(req.body && req.body.count, 10) || 1;
    count = Math.max(1, Math.min(500, count));

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
            lastSeen: null,
            session: null
        };
        created.push({ key, id });
    }

    saveKeys();
    res.json({ generated: created });
});

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

app.post("/api/admin/delete-all", requireAdmin, (req, res) => {
    keys = {};
    saveKeys();
    res.json({ success: true });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
    let total = 0;
    let active = 0;
    let inactive = 0;
    const activeList = [];

    for (const k in keys) {
        const record = keys[k];
        normalizeRecord(record);

        total++;
        if (record.active) {
            active++;
            activeList.push({
                key: k,
                id: record.id,
                clientId: record.clientId,
                hw: record.hw,
                activatedAt: record.activatedAt,
                lastSeen: record.lastSeen,
                sessionExpiresAt: record.session?.expiresAt || null
            });
        } else {
            inactive++;
        }
    }

    saveKeys();
    res.json({ total, active, inactive, activeList });
});

app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/api/admin/keys.json", requireAdmin, (req, res) => {
    res.sendFile(KEY_FILE);
});

app.listen(PORT, () => {
    console.log("License server running on port", PORT);
});
