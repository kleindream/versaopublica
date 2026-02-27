const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const multer = require("multer");

const { db, init } = require("./db");
init();

const app = express();
const PORT = process.env.PORT || 3000;

// Pastas garantidas
const uploadsDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Config EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: "./data" }),
    secret: process.env.SESSION_SECRET || "kleindream_dev_secret",
    resave: false,
    saveUninitialized: false
  })
);

// Helpers
function getUserById(id) {
  return db.prepare("SELECT id, email, username, full_name, bio, city, state, created_at FROM users WHERE id=?").get(id);
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

function addNotif(userId, type, text, link = null) {
  db.prepare("INSERT INTO notifications (user_id, type, text, link) VALUES (?,?,?,?)").run(userId, type, text, link);
}

app.use((req, res, next) => {
  res.locals.me = req.session.userId ? getUserById(req.session.userId) : null;
  if (req.session.userId) {
    const notifs = db.prepare("SELECT * FROM notifications WHERE user_id=? AND is_read=0 ORDER BY created_at DESC LIMIT 20").all(req.session.userId);
    res.locals.notifCount = notifs.length;
  } else {
    res.locals.notifCount = 0;
  }
  next();
});

// Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safe = Date.now() + "_" + Math.random().toString(16).slice(2) + path.extname(file.originalname).toLowerCase();
    cb(null, safe);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 },
});

// ===== ROTAS PÚBLICAS =====
app.get("/", (req, res) => res.render("index"));

app.get("/register", (req, res) => res.render("register", { error: null }));
app.post("/register", (req, res) => {
  const { email, username, password, full_name } = req.body;

  if (!email || !username || !password) return res.render("register", { error: "Preencha e-mail, usuário e senha." });
  if (password.length < 4) return res.render("register", { error: "Senha muito curta (mínimo 4)." });

  const exists = db.prepare("SELECT 1 FROM users WHERE email=? OR username=?").get(email, username);
  if (exists) return res.render("register", { error: "E-mail ou usuário já existe." });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users (email, username, password_hash, full_name) VALUES (?,?,?,?)").run(email, username, hash, full_name || null);

  req.session.userId = info.lastInsertRowid;
  res.redirect("/home");
});

app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", (req, res) => {
  const { usernameOrEmail, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email=? OR username=?").get(usernameOrEmail, usernameOrEmail);
  if (!user) return res.render("login", { error: "Usuário não encontrado." });

  const ok = bcrypt.compareSync(password || "", user.password_hash);
  if (!ok) return res.render("login", { error: "Senha incorreta." });

  req.session.userId = user.id;
  res.redirect("/home");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===== HOME =====
app.get("/home", requireAuth, (req, res) => {
  const meId = req.session.userId;

  const incomingRequests = db.prepare(`
    SELECT fr.id, u.id AS user_id, u.username, u.full_name
    FROM friend_requests fr
    JOIN users u ON u.id = fr.from_user_id
    WHERE fr.to_user_id=? AND fr.status='pending'
    ORDER BY fr.created_at DESC
  `).all(meId);

  const pendingTestimonials = db.prepare(`
    SELECT t.id, u.id AS user_id, u.username, u.full_name, t.created_at
    FROM testimonials t
    JOIN users u ON u.id = t.from_user_id
    WHERE t.to_user_id=? AND t.status='pending'
    ORDER BY t.created_at DESC
  `).all(meId);

  const unreadMessages = db.prepare(`
    SELECT m.id, u.username AS from_username, m.subject, m.created_at
    FROM messages m
    JOIN users u ON u.id = m.from_user_id
    WHERE m.to_user_id=? AND m.is_read=0
    ORDER BY m.created_at DESC
    LIMIT 10
  `).all(meId);

  const latestScraps = db.prepare(`
    SELECT s.id, s.content, s.created_at, u.username AS from_username, u.id AS from_id
    FROM scraps s
    JOIN users u ON u.id = s.from_user_id
    WHERE s.to_user_id=?
    ORDER BY s.created_at DESC
    LIMIT 10
  `).all(meId);

  res.render("home", { incomingRequests, pendingTestimonials, unreadMessages, latestScraps });
});

// ===== PERFIL =====
app.get("/u/:username", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const user = db.prepare("SELECT id, username, full_name, bio, city, state, created_at FROM users WHERE username=?").get(req.params.username);
  if (!user) return res.status(404).send("Usuário não encontrado.");

  const isMe = user.id === meId;

  const friend = db.prepare("SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?").get(meId, user.id);

  const reqOut = db.prepare("SELECT status FROM friend_requests WHERE from_user_id=? AND to_user_id=?").get(meId, user.id);
  const reqIn = db.prepare("SELECT status FROM friend_requests WHERE from_user_id=? AND to_user_id=?").get(user.id, meId);

  const scraps = db.prepare(`
    SELECT s.id, s.content, s.created_at, u.username AS from_username
    FROM scraps s
    JOIN users u ON u.id = s.from_user_id
    WHERE s.to_user_id=?
    ORDER BY s.created_at DESC
    LIMIT 20
  `).all(user.id);

  const testimonials = db.prepare(`
    SELECT t.id, t.content, t.created_at, u.username AS from_username
    FROM testimonials t
    JOIN users u ON u.id = t.from_user_id
    WHERE t.to_user_id=? AND t.status='approved'
    ORDER BY t.created_at DESC
    LIMIT 20
  `).all(user.id);

  const friendsCount = db.prepare("SELECT COUNT(*) AS c FROM friendships WHERE user_id=?").get(user.id).c;

  res.render("profile", { user, isMe, friend: !!friend, reqOut, reqIn, scraps, testimonials, friendsCount });
});

app.get("/profile/edit", requireAuth, (req, res) => {
  const me = getUserById(req.session.userId);
  res.render("profile_edit", { me, error: null, ok: null });
});

app.post("/profile/edit", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const { full_name, bio, city, state } = req.body;

  db.prepare("UPDATE users SET full_name=?, bio=?, city=?, state=? WHERE id=?")
    .run(full_name || null, bio || null, city || null, state || null, meId);

  res.render("profile_edit", { me: getUserById(meId), error: null, ok: "Perfil atualizado." });
});

// ===== AMIZADES =====
app.get("/friends", requireAuth, (req, res) => {
  const meId = req.session.userId;

  const friends = db.prepare(`
    SELECT u.id, u.username, u.full_name
    FROM friendships f
    JOIN users u ON u.id = f.friend_id
    WHERE f.user_id=?
    ORDER BY u.username
  `).all(meId);

  const incomingRequests = db.prepare(`
    SELECT fr.id, u.id AS user_id, u.username, u.full_name, fr.created_at
    FROM friend_requests fr
    JOIN users u ON u.id = fr.from_user_id
    WHERE fr.to_user_id=? AND fr.status='pending'
    ORDER BY fr.created_at DESC
  `).all(meId);

  const outgoingRequests = db.prepare(`
    SELECT fr.id, u.id AS user_id, u.username, u.full_name, fr.status, fr.created_at
    FROM friend_requests fr
    JOIN users u ON u.id = fr.to_user_id
    WHERE fr.from_user_id=?
    ORDER BY fr.created_at DESC
  `).all(meId);

  res.render("friends", { friends, incomingRequests, outgoingRequests });
});

app.post("/friends/request/:userId", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const otherId = Number(req.params.userId);
  if (otherId === meId) return res.redirect("back");

  const already = db.prepare("SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?").get(meId, otherId);
  if (already) return res.redirect("back");

  try {
    db.prepare("INSERT INTO friend_requests (from_user_id, to_user_id) VALUES (?,?)").run(meId, otherId);
    addNotif(otherId, "friend_request", "Você recebeu um pedido de amizade.", "/friends");
  } catch (e) {}
  res.redirect("back");
});

app.post("/friends/accept/:requestId", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const reqId = Number(req.params.requestId);

  const fr = db.prepare("SELECT * FROM friend_requests WHERE id=? AND to_user_id=?").get(reqId, meId);
  if (!fr) return res.redirect("/friends");

  db.prepare("UPDATE friend_requests SET status='accepted' WHERE id=?").run(reqId);

  db.prepare("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?,?)").run(fr.from_user_id, fr.to_user_id);
  db.prepare("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?,?)").run(fr.to_user_id, fr.from_user_id);

  addNotif(fr.from_user_id, "friend_accept", "Seu pedido de amizade foi aceito.", `/u/${getUserById(meId).username}`);
  res.redirect("/friends");
});

app.post("/friends/reject/:requestId", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const reqId = Number(req.params.requestId);
  db.prepare("UPDATE friend_requests SET status='rejected' WHERE id=? AND to_user_id=?").run(reqId, meId);
  res.redirect("/friends");
});

app.post("/friends/remove/:userId", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const otherId = Number(req.params.userId);
  db.prepare("DELETE FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)")
    .run(meId, otherId, otherId, meId);
  res.redirect("/friends");
});

// ===== RECADOS =====
app.get("/scraps/:username", requireAuth, (req, res) => {
  const user = db.prepare("SELECT id, username, full_name FROM users WHERE username=?").get(req.params.username);
  if (!user) return res.status(404).send("Usuário não encontrado.");

  const scraps = db.prepare(`
    SELECT s.id, s.content, s.created_at, u.username AS from_username, u.id AS from_id
    FROM scraps s
    JOIN users u ON u.id = s.from_user_id
    WHERE s.to_user_id=?
    ORDER BY s.created_at DESC
    LIMIT 100
  `).all(user.id);

  res.render("scraps", { user, scraps });
});

app.post("/scraps/:username", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const { content } = req.body;
  const to = db.prepare("SELECT id FROM users WHERE username=?").get(req.params.username);
  if (!to) return res.redirect("/home");
  if (!content || !content.trim()) return res.redirect(`/scraps/${req.params.username}`);

  db.prepare("INSERT INTO scraps (from_user_id, to_user_id, content) VALUES (?,?,?)").run(meId, to.id, content.trim());
  addNotif(to.id, "scrap", "Você recebeu um recado.", `/scraps/${req.params.username}`);
  res.redirect(`/scraps/${req.params.username}`);
});

// ===== DEPOIMENTOS =====
app.get("/testimonials/:username", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const user = db.prepare("SELECT id, username, full_name FROM users WHERE username=?").get(req.params.username);
  if (!user) return res.status(404).send("Usuário não encontrado.");

  const approved = db.prepare(`
    SELECT t.id, t.content, t.created_at, u.username AS from_username
    FROM testimonials t
    JOIN users u ON u.id = t.from_user_id
    WHERE t.to_user_id=? AND t.status='approved'
    ORDER BY t.created_at DESC
  `).all(user.id);

  const pendingMine = (user.id === meId)
    ? db.prepare(`
        SELECT t.id, t.content, t.created_at, u.username AS from_username
        FROM testimonials t
        JOIN users u ON u.id = t.from_user_id
        WHERE t.to_user_id=? AND t.status='pending'
        ORDER BY t.created_at DESC
      `).all(user.id)
    : [];

  res.render("testimonials", { user, approved, pendingMine });
});

app.post("/testimonials/:username", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const { content } = req.body;
  const to = db.prepare("SELECT id FROM users WHERE username=?").get(req.params.username);
  if (!to) return res.redirect("/home");
  if (!content || !content.trim()) return res.redirect(`/testimonials/${req.params.username}`);

  db.prepare("INSERT INTO testimonials (from_user_id, to_user_id, content) VALUES (?,?,?)")
    .run(meId, to.id, content.trim());

  addNotif(to.id, "testimonial", "Você recebeu um depoimento para aprovar.", "/testimonials/" + req.params.username);
  res.redirect(`/testimonials/${req.params.username}`);
});

app.post("/testimonials/approve/:id", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const t = db.prepare("SELECT * FROM testimonials WHERE id=? AND to_user_id=?").get(Number(req.params.id), meId);
  if (t) {
    db.prepare("UPDATE testimonials SET status='approved' WHERE id=?").run(t.id);
    addNotif(t.from_user_id, "testimonial_approved", "Seu depoimento foi aprovado.", `/u/${getUserById(meId).username}`);
  }
  res.redirect("back");
});

app.post("/testimonials/reject/:id", requireAuth, (req, res) => {
  const meId = req.session.userId;
  db.prepare("UPDATE testimonials SET status='rejected' WHERE id=? AND to_user_id=?").run(Number(req.params.id), meId);
  res.redirect("back");
});

// ===== FOTOS / ÁLBUNS =====
app.get("/photos/:username", requireAuth, (req, res) => {
  const user = db.prepare("SELECT id, username, full_name FROM users WHERE username=?").get(req.params.username);
  if (!user) return res.status(404).send("Usuário não encontrado.");

  const albums = db.prepare("SELECT * FROM albums WHERE user_id=? ORDER BY created_at DESC").all(user.id);
  const photos = db.prepare("SELECT * FROM photos WHERE user_id=? ORDER BY created_at DESC LIMIT 80").all(user.id);

  res.render("photos", { user, albums, photos });
});

app.post("/albums/create", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const title = (req.body.title || "").trim();
  if (!title) return res.redirect(`/photos/${getUserById(meId).username}`);
  db.prepare("INSERT INTO albums (user_id, title) VALUES (?,?)").run(meId, title);
  res.redirect(`/photos/${getUserById(meId).username}`);
});

app.post("/photos/upload/:albumId", requireAuth, upload.single("photo"), (req, res) => {
  const meId = req.session.userId;
  const albumId = Number(req.params.albumId);

  const album = db.prepare("SELECT * FROM albums WHERE id=? AND user_id=?").get(albumId, meId);
  if (!album) return res.redirect(`/photos/${getUserById(meId).username}`);

  if (!req.file) return res.redirect(`/photos/${getUserById(meId).username}`);

  const caption = (req.body.caption || "").trim();
  db.prepare("INSERT INTO photos (album_id, user_id, filename, caption) VALUES (?,?,?,?)")
    .run(albumId, meId, req.file.filename, caption || null);

  res.redirect(`/photos/${getUserById(meId).username}`);
});

// ===== GRUPOS =====
app.get("/groups", requireAuth, (req, res) => {
  const meId = req.session.userId;

  const groups = db.prepare(`
    SELECT g.*, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id=g.id) AS members
    FROM groups g
    ORDER BY g.created_at DESC
    LIMIT 200
  `).all();

  const myGroups = db.prepare(`
    SELECT g.*
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id
    WHERE gm.user_id=?
    ORDER BY g.name
  `).all(meId);

  res.render("groups", { groups, myGroups, error: null });
});

app.post("/groups/create", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const name = (req.body.name || "").trim();
  const description = (req.body.description || "").trim();
  const category = (req.body.category || "").trim();

  if (!name) {
    const groups = db.prepare("SELECT * FROM groups ORDER BY created_at DESC LIMIT 200").all();
    const myGroups = db.prepare(`
      SELECT g.*
      FROM group_members gm
      JOIN groups g ON g.id = gm.group_id
      WHERE gm.user_id=?
      ORDER BY g.name
    `).all(meId);
    return res.render("groups", { groups, myGroups, error: "Nome do grupo é obrigatório." });
  }

  const info = db.prepare("INSERT INTO groups (owner_id, name, description, category) VALUES (?,?,?,?)")
    .run(meId, name, description || null, category || null);

  const groupId = info.lastInsertRowid;
  db.prepare("INSERT INTO group_members (group_id, user_id, role) VALUES (?,?, 'owner')").run(groupId, meId);

  res.redirect(`/groups/${groupId}`);
});

app.get("/groups/:id", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const groupId = Number(req.params.id);

  const group = db.prepare("SELECT * FROM groups WHERE id=?").get(groupId);
  if (!group) return res.status(404).send("Grupo não encontrado.");

  const membership = db.prepare("SELECT * FROM group_members WHERE group_id=? AND user_id=?").get(groupId, meId);

  const members = db.prepare(`
    SELECT u.username, u.full_name, gm.role
    FROM group_members gm
    JOIN users u ON u.id = gm.user_id
    WHERE gm.group_id=?
    ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'mod' THEN 1 ELSE 2 END, u.username
    LIMIT 200
  `).all(groupId);

  const topics = db.prepare(`
    SELECT t.*, u.username AS author
    FROM group_topics t
    JOIN users u ON u.id = t.user_id
    WHERE t.group_id=?
    ORDER BY t.created_at DESC
    LIMIT 100
  `).all(groupId);

  res.render("group_view", { group, membership, members, topics });
});

app.post("/groups/:id/join", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const groupId = Number(req.params.id);
  const group = db.prepare("SELECT * FROM groups WHERE id=?").get(groupId);
  if (!group) return res.redirect("/groups");

  db.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?,?, 'member')").run(groupId, meId);
  res.redirect(`/groups/${groupId}`);
});

app.post("/groups/:id/leave", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const groupId = Number(req.params.id);

  const role = db.prepare("SELECT role FROM group_members WHERE group_id=? AND user_id=?").get(groupId, meId);
  if (role && role.role === "owner") return res.redirect(`/groups/${groupId}`);

  db.prepare("DELETE FROM group_members WHERE group_id=? AND user_id=?").run(groupId, meId);
  res.redirect(`/groups/${groupId}`);
});

app.post("/groups/:id/topics/create", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const groupId = Number(req.params.id);
  const title = (req.body.title || "").trim();
  const content = (req.body.content || "").trim();

  const membership = db.prepare("SELECT * FROM group_members WHERE group_id=? AND user_id=?").get(groupId, meId);
  if (!membership) return res.redirect(`/groups/${groupId}`);

  if (!title || !content) return res.redirect(`/groups/${groupId}`);

  const info = db.prepare("INSERT INTO group_topics (group_id, user_id, title) VALUES (?,?,?)").run(groupId, meId, title);
  const topicId = info.lastInsertRowid;

  db.prepare("INSERT INTO group_posts (topic_id, user_id, content) VALUES (?,?,?)").run(topicId, meId, content);
  res.redirect(`/groups/${groupId}/topic/${topicId}`);
});

app.get("/groups/:groupId/topic/:topicId", requireAuth, (req, res) => {
  const groupId = Number(req.params.groupId);
  const topicId = Number(req.params.topicId);
  const meId = req.session.userId;

  const group = db.prepare("SELECT * FROM groups WHERE id=?").get(groupId);
  const topic = db.prepare(`
    SELECT t.*, u.username AS author
    FROM group_topics t
    JOIN users u ON u.id = t.user_id
    WHERE t.id=? AND t.group_id=?
  `).get(topicId, groupId);

  if (!group || !topic) return res.status(404).send("Tópico não encontrado.");

  const membership = db.prepare("SELECT * FROM group_members WHERE group_id=? AND user_id=?").get(groupId, meId);

  const posts = db.prepare(`
    SELECT p.*, u.username AS author
    FROM group_posts p
    JOIN users u ON u.id = p.user_id
    WHERE p.topic_id=?
    ORDER BY p.created_at ASC
  `).all(topicId);

  res.render("group_topic", { group, topic, posts, membership });
});

app.post("/groups/:groupId/topic/:topicId/reply", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const groupId = Number(req.params.groupId);
  const topicId = Number(req.params.topicId);
  const content = (req.body.content || "").trim();

  const membership = db.prepare("SELECT * FROM group_members WHERE group_id=? AND user_id=?").get(groupId, meId);
  if (!membership) return res.redirect(`/groups/${groupId}`);

  if (!content) return res.redirect(`/groups/${groupId}/topic/${topicId}`);

  db.prepare("INSERT INTO group_posts (topic_id, user_id, content) VALUES (?,?,?)").run(topicId, meId, content);
  res.redirect(`/groups/${groupId}/topic/${topicId}`);
});

// ===== MENSAGENS =====
app.get("/messages", requireAuth, (req, res) => {
  const meId = req.session.userId;

  const inbox = db.prepare(`
    SELECT m.*, u.username AS from_username
    FROM messages m
    JOIN users u ON u.id = m.from_user_id
    WHERE m.to_user_id=?
    ORDER BY m.created_at DESC
    LIMIT 100
  `).all(meId);

  const outbox = db.prepare(`
    SELECT m.*, u.username AS to_username
    FROM messages m
    JOIN users u ON u.id = m.to_user_id
    WHERE m.from_user_id=?
    ORDER BY m.created_at DESC
    LIMIT 100
  `).all(meId);

  res.render("messages", { inbox, outbox, error: null, ok: null });
});

app.post("/messages/send", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const toUsername = (req.body.to || "").trim();
  const subject = (req.body.subject || "").trim();
  const body = (req.body.body || "").trim();

  const to = db.prepare("SELECT id FROM users WHERE username=?").get(toUsername);
  if (!to) {
    return res.render("messages", { inbox: [], outbox: [], error: "Usuário destino não encontrado.", ok: null });
  }
  if (!subject || !body) {
    return res.render("messages", { inbox: [], outbox: [], error: "Assunto e mensagem são obrigatórios.", ok: null });
  }

  db.prepare("INSERT INTO messages (from_user_id, to_user_id, subject, body) VALUES (?,?,?,?)")
    .run(meId, to.id, subject, body);

  addNotif(to.id, "message", "Você recebeu uma mensagem.", "/messages");
  res.redirect("/messages");
});

app.get("/messages/:id", requireAuth, (req, res) => {
  const meId = req.session.userId;
  const id = Number(req.params.id);

  const msg = db.prepare(`
    SELECT m.*, u.username AS from_username, u2.username AS to_username
    FROM messages m
    JOIN users u ON u.id = m.from_user_id
    JOIN users u2 ON u2.id = m.to_user_id
    WHERE m.id=? AND (m.to_user_id=? OR m.from_user_id=?)
  `).get(id, meId, meId);

  if (!msg) return res.status(404).send("Mensagem não encontrada.");

  if (msg.to_user_id === meId && msg.is_read === 0) {
    db.prepare("UPDATE messages SET is_read=1 WHERE id=?").run(id);
  }

  res.render("message_view", { msg });
});

// ===== BUSCA =====
app.get("/search", requireAuth, (req, res) => {
  const q = (req.query.q || "").trim();
  const type = (req.query.type || "people").trim();

  let people = [];
  let groups = [];

  if (q) {
    if (type === "groups") {
      groups = db.prepare(`
        SELECT g.*, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id=g.id) AS members
        FROM groups g
        WHERE g.name LIKE ? OR g.description LIKE ?
        ORDER BY g.name
        LIMIT 100
      `).all(`%${q}%`, `%${q}%`);
    } else {
      people = db.prepare(`
        SELECT id, username, full_name, city, state
        FROM users
        WHERE username LIKE ? OR full_name LIKE ? OR city LIKE ?
        ORDER BY username
        LIMIT 100
      `).all(`%${q}%`, `%${q}%`, `%${q}%`);
    }
  }

  res.render("search", { q, type, people, groups });
});

// ===== NOTIFICAÇÕES =====
app.get("/notifications", requireAuth, (req, res) => {
  const meId = req.session.userId;

  const notifs = db.prepare(`
    SELECT * FROM notifications
    WHERE user_id=?
    ORDER BY created_at DESC
    LIMIT 200
  `).all(meId);

  res.render("notifications", { notifs });
});

app.post("/notifications/readall", requireAuth, (req, res) => {
  const meId = req.session.userId;
  db.prepare("UPDATE notifications SET is_read=1 WHERE user_id=?").run(meId);
  res.redirect("/notifications");
});

// ===== START =====
app.listen(PORT, () => {
  console.log(`KleinDream rodando em http://localhost:${PORT}`);
});
