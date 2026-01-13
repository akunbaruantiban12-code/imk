const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static("public"));

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authHttp(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ===================== REST API =====================

// Register
app.post("/api/register", (req, res) => {
  const username = String(req.body.username || "").trim().slice(0, 20);
  const password = String(req.body.password || "");

  if (!username || password.length < 6) {
    return res
      .status(400)
      .json({ error: "Username wajib & password minimal 6 karakter" });
  }

  const password_hash = bcrypt.hashSync(password, 10);
  const created_at = Date.now();

  try {
    const stmt = db.prepare(
      "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)"
    );
    const info = stmt.run(username, password_hash, created_at);
    const user = { id: info.lastInsertRowid, username };
    return res.json({ token: signToken(user), user });
  } catch (e) {
    return res.status(400).json({ error: "Username sudah dipakai" });
  }
});

// Login
app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db
    .prepare("SELECT id, username, password_hash FROM users WHERE username=?")
    .get(username);

  if (!user) return res.status(400).json({ error: "User tidak ditemukan" });

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Password salah" });

  return res.json({
    token: signToken(user),
    user: { id: user.id, username: user.username },
  });
});

// Me
app.get("/api/me", authHttp, (req, res) => {
  res.json({ user: req.user });
});

// List users
app.get("/api/users", authHttp, (req, res) => {
  const users = db
    .prepare("SELECT id, username FROM users WHERE id != ? ORDER BY username ASC")
    .all(req.user.id);
  res.json({ users });
});

// ===================== CHAT HISTORY =====================

// Get chat history
app.get("/api/messages/:otherId", authHttp, (req, res) => {
  const otherId = Number(req.params.otherId);
  if (!otherId) return res.status(400).json({ error: "otherId invalid" });

  const rows = db
    .prepare(`
      SELECT id, sender_id, receiver_id, text, created_at
      FROM messages
      WHERE (sender_id=? AND receiver_id=?)
         OR (sender_id=? AND receiver_id=?)
      ORDER BY created_at ASC
      LIMIT 200
    `)
    .all(req.user.id, otherId, otherId, req.user.id);

  res.json({ messages: rows });
});

// ===================== HAPUS HISTORY CHAT =====================
app.delete("/api/messages/:otherId", authHttp, (req, res) => {
  const otherId = Number(req.params.otherId);
  if (!otherId) {
    return res.status(400).json({ error: "otherId invalid" });
  }

  db.prepare(`
    DELETE FROM messages
    WHERE (sender_id=? AND receiver_id=?)
       OR (sender_id=? AND receiver_id=?)
  `).run(
    req.user.id,
    otherId,
    otherId,
    req.user.id
  );

  res.json({ success: true });
});

// ===================== HAPUS KONTAK (AMAN) =====================
app.delete("/api/contacts/:contactId", authHttp, (req, res) => {
  const contactId = Number(req.params.contactId);
  if (!contactId) {
    return res.status(400).json({ error: "contactId invalid" });
  }

  // Tidak menghapus user (karena tidak ada tabel contacts)
  // Frontend cukup sembunyikan kontak
  res.json({ success: true });
});

// ===================== SOCKET AUTH =====================
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("Missing token"));
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

function userRoom(userId) {
  return `user:${userId}`;
}

// ===================== REALTIME DM =====================
io.on("connection", (socket) => {
  const me = socket.user;
  socket.join(userRoom(me.id));

  socket.on("dm", (payload) => {
    const to = Number(payload?.toUserId);
    const text = String(payload?.text || "").trim();
    if (!to || !text) return;

    const msg = {
      sender_id: me.id,
      receiver_id: to,
      text: text.slice(0, 500),
      created_at: Date.now(),
    };

    const info = db
      .prepare(
        "INSERT INTO messages (sender_id, receiver_id, text, created_at) VALUES (?,?,?,?)"
      )
      .run(
        msg.sender_id,
        msg.receiver_id,
        msg.text,
        msg.created_at
      );

    const out = { id: info.lastInsertRowid, ...msg };

    io.to(userRoom(to)).emit("dm", out);
    io.to(userRoom(me.id)).emit("dm", out);
  });
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Running on ${PORT}`);
});
