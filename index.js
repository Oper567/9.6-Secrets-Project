import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import pgSession from "connect-pg-simple"; 
import flash from "connect-flash";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const PostgresStore = pgSession(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

/* ---------------- DATABASE ---------------- */
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000, 
  idleTimeoutMillis: 30000,       
  max: 10                          
});

db.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

/* ---------------- SUPABASE STORAGE & AUTH ---------------- */
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const upload = multer({ storage: multer.memoryStorage() });

/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); 
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// HTTPS Redirect for Production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.get('host') + req.url);
  }
  next();
});

app.use(session({
  store: new PostgresStore({ 
    pool: db, 
    tableName: 'session', 
    createTableIfMissing: true,
    pruneSessionInterval: 60 * 30 
  }),
  secret: process.env.SESSION_SECRET || "apugo_secret",
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24, 
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? 'none' : 'lax' 
  }
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

/* ---------------- HELPERS & GATEKEEPERS ---------------- */

async function sendWelcomeNote(userId) {
  try {
    await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, 1, $2)", 
    [userId, "Welcome to Apugo Village! 🌴"]);
  } catch (err) { console.error("Notification Error:", err); }
}

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') return next();
  req.flash("error", "Access denied. Elders only!");
  res.redirect("/feed");
}

function isVerified(req, res, next) {
  if (req.isAuthenticated() && req.user.is_verified) return next();
  req.flash("error", "Please verify your email to interact with the village.");
  res.redirect("/profile");
}

app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.messages = req.flash();
  res.locals.unreadCount = 0;
  if (req.isAuthenticated()) {
    try {
      await db.query("UPDATE users SET last_active = NOW() WHERE id = $1", [req.user.id]);
      const noteCount = await db.query("SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false", [req.user.id]);
      res.locals.unreadCount = noteCount.rows[0].count;
    } catch (e) { console.error("Middleware DB Error:", e); }
  }
  next();
});

/* ---------------- PASSPORT ---------------- */

passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (!result.rows.length) return done(null, false, { message: "User not found" });
    const user = result.rows[0];
    if (user.password === "google-oauth") return done(null, false, { message: "Use Google Sign-In" });
    const valid = await bcrypt.compare(password, user.password);
    return valid ? done(null, user) : done(null, false, { message: "Wrong password" });
  } catch (err) { done(err); }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  proxy: true 
}, async (token, secret, profile, done) => {
  try {
    const email = profile.emails[0].value.toLowerCase();
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) return done(null, result.rows[0]);
    const newUser = await db.query(
        "INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", 
        [email, "google-oauth", "user", true]
    );
    await sendWelcomeNote(newUser.rows[0].id);
    return done(null, newUser.rows[0]);
  } catch (err) { return done(err); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, result.rows[0]);
  } catch (e) { done(e); }
});

/* ---------------- ROUTES ---------------- */

app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (password.length < 8) {
    req.flash("error", "Password must be at least 8 characters long.");
    return res.redirect("/register");
  }
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    const user = await db.query("INSERT INTO users (email, password, role, is_verified) VALUES ($1,$2,$3,$4) RETURNING *", [email.toLowerCase(), hash, "user", true]);
    await sendWelcomeNote(user.rows[0].id);
    req.login(user.rows[0], () => res.redirect("/feed"));
  } catch (err) { 
    req.flash("error", "Email already registered.");
    res.redirect("/register"); 
  }
});

app.post("/login", passport.authenticate("local", { successRedirect: "/feed", failureRedirect: "/login", failureFlash: true }));
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => res.redirect("/feed"));

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

/* --- FRIENDSHIP SYSTEM --- */

app.post("/friends/request/:id", async (req, res) => {
  // 1. Prevent adding yourself
  if (!req.isAuthenticated() || req.user.id == req.params.id) {
      return res.redirect("/feed");
  }
  
  try {
    // 2. Insert request using the ID from the URL (:id)
    await db.query(
      "INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, 'pending') ON CONFLICT DO NOTHING", 
      [req.user.id, req.params.id]
    );

    // 3. Send notification to the person BEING added (req.params.id)
    await db.query(
      "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)", 
      [req.params.id, req.user.id, "Sent you a village friend request! 🤝"]
    );

    res.redirect(req.get("Referrer") || "/feed");
  } catch (err) { 
    console.error("Add Friend Error:", err);
    res.redirect("/feed"); 
  }
});

app.post("/friends/accept/:senderId", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    await db.query("UPDATE friendships SET status = 'accepted' WHERE sender_id = $1 AND receiver_id = $2", [req.params.senderId, req.user.id]);
    await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)", [req.params.senderId, req.user.id, "Accepted your friend request! 🌴"]);
    res.redirect("back");
  } catch (err) { res.redirect("back"); }
});

/* --- DISCOVER & FEED --- */

app.get("/discover", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const discoverPosts = await db.query(`
      SELECT e.*, u.email AS author, u.is_verified,
      (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes_count
      FROM events e JOIN users u ON e.created_by=u.id 
      WHERE e.is_deleted=false ORDER BY RANDOM() LIMIT 24
    `);
    res.render("discover", { posts: discoverPosts.rows, search: "" });
  } catch (err) { res.redirect("/feed"); }
});

app.get("/feed", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const search = req.query.search || "";
  try {
    const announcements = await db.query(`SELECT e.*, u.email AS author FROM events e JOIN users u ON e.created_by=u.id WHERE is_announcement=true AND is_deleted=false ORDER BY created_at DESC`);
    const trending = await db.query(`SELECT e.id, e.description, COUNT(l.id) as likes_count FROM events e LEFT JOIN likes l ON e.id = l.event_id WHERE e.is_deleted = false GROUP BY e.id ORDER BY likes_count DESC LIMIT 3`);
    
    let postsQuery = `
      SELECT e.*, u.email AS author, u.last_active, u.is_verified, 
      (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes_count,
      (SELECT status FROM friendships WHERE (sender_id = $1 AND receiver_id = e.created_by) OR (sender_id = e.created_by AND receiver_id = $1) LIMIT 1) as friend_status,
      (SELECT JSON_AGG(json_build_object('content', c.content, 'author', cu.email)) FROM comments c JOIN users cu ON c.user_id = cu.id WHERE c.event_id = e.id) as comments_list
      FROM events e JOIN users u ON e.created_by=u.id 
      WHERE is_announcement=false AND is_deleted=false
    `;
    
    const params = [req.user.id];
    if (search) { 
      postsQuery += ` AND (e.description ILIKE $2)`; 
      params.push(`%${search}%`); 
    }
    postsQuery += ` ORDER BY e.is_pinned DESC, e.created_at DESC`;
    
    const posts = await db.query(postsQuery, params);
    res.render("feed", { announcements: announcements.rows, posts: posts.rows, trending: trending.rows, search });
  } catch (err) { console.error(err); res.status(500).send("Error loading feed"); }
});

/* --- CHAT SYSTEM --- */

app.get("/messages", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const friends = await db.query(`
        SELECT u.id, u.email FROM users u
        JOIN friendships f ON (f.sender_id = u.id OR f.receiver_id = u.id)
        WHERE (f.sender_id = $1 OR f.receiver_id = $1) AND u.id != $1 AND f.status = 'accepted'`, [req.user.id]);
    
    res.render("messages", { 
        friends: friends.rows, 
        targetUser: req.query.userId || null, 
        search: "" 
    });
  } catch (err) { res.redirect("/feed"); }
});

app.get("/api/chat/:friendId", async (req, res) => {
  if (!req.isAuthenticated()) return res.json([]);
  const result = await db.query(`
      SELECT * FROM messages 
      WHERE (sender_id = $1 AND receiver_id = $2) 
      OR (sender_id = $2 AND receiver_id = $1)
      ORDER BY created_at ASC`, [req.user.id, req.params.friendId]);
  res.json(result.rows);
});

app.post("/api/chat/send", async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Unauthorized" });
  
  const { receiverId, content } = req.body;
  
  // Basic validation to prevent empty messages
  if (!content || !receiverId) {
    return res.status(400).json({ error: "Missing content or recipient" });
  }

  try {
      const msg = await db.query(
        "INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING *", 
        [req.user.id, receiverId, content]
      );
      res.json(msg.rows[0]);
  } catch (err) {
      console.error("CRITICAL DATABASE ERROR:", err.message); // This will show the real error in your terminal
      res.status(500).json({ error: err.message });
  }
});

/* --- ACTIONS (EVENTS & COMMENTS) --- */

app.post("/event/create", isVerified, upload.single("localMedia"), async (req, res) => {
  try {
    let mediaUrl = null;
    let mediaType = 'image';
    if (req.file) {
      const fileName = `${Date.now()}-${req.file.originalname}`;
      await supabase.storage.from('apugo_village').upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });
      const { data: publicData } = supabase.storage.from('apugo_village').getPublicUrl(fileName);
      mediaUrl = publicData.publicUrl;
      mediaType = req.file.mimetype.startsWith("video") ? 'video' : 'image';
    }
    await db.query("INSERT INTO events (title, description, image_url, created_by, is_announcement, media_type) VALUES ($1,$2,$3,$4,$5,$6)", 
      ["Post", req.body.description, mediaUrl, req.user.id, req.user.role === 'admin', mediaType]);
    res.redirect("/feed");
  } catch (err) { res.redirect("/feed"); }
});

app.post("/event/:id/like", isVerified, async (req, res) => {
  try {
    const check = await db.query("SELECT * FROM likes WHERE user_id=$1 AND event_id=$2", [req.user.id, req.params.id]);
    if (check.rows.length) {
      await db.query("DELETE FROM likes WHERE user_id=$1 AND event_id=$2", [req.user.id, req.params.id]);
    } else {
      await db.query("INSERT INTO likes (user_id,event_id) VALUES ($1,$2)", [req.user.id, req.params.id]);
    }
    res.redirect("back");
  } catch (err) { res.redirect("back"); }
});

app.post("/event/:id/comment", isVerified, async (req, res) => {
  try {
    await db.query("INSERT INTO comments (event_id, user_id, content) VALUES ($1, $2, $3)", 
      [req.params.id, req.user.id, req.body.content]);
    res.redirect("back");
  } catch (err) { res.redirect("back"); }
});
app.post("/event/:id/delete", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  
  try {
    // 1. Find the post to check ownership
    const post = await db.query("SELECT created_by FROM events WHERE id = $1", [req.params.id]);
    
    if (post.rows.length > 0) {
      const isOwner = post.rows[0].created_by === req.user.id;
      const isAdmin = req.user.role === 'admin';

      // 2. Only allow the owner or an admin to delete
      if (isOwner || isAdmin) {
        await db.query("UPDATE events SET is_deleted = true WHERE id = $1", [req.params.id]);
        req.flash("success", "Post removed from the square.");
      } else {
        req.flash("error", "You don't have permission to do that.");
      }
    }
    res.redirect("back");
  } catch (err) {
    console.error(err);
    res.redirect("/feed");
  }
});

/* --- PROFILE & ADMIN --- */

app.get("/profile", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const result = await db.query("SELECT * FROM events WHERE created_by = $1 AND is_deleted = false ORDER BY created_at DESC", [req.user.id]);
    res.render("profile", { posts: result.rows, search: "" });
  } catch (e) { res.redirect("/feed"); }
});

app.get("/settings", (req, res) => req.isAuthenticated() ? res.render("settings", { user: req.user, search: "" }) : res.redirect("/login"));

app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await db.query("SELECT id, email, role, is_verified FROM users ORDER BY id DESC");
    res.render("admin-dashboard", { users: users.rows, search: "" });
  } catch (err) { res.redirect("/feed"); }
});

app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));