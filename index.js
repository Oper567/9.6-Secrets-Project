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

/* ---------------- SUPABASE STORAGE & AUTH ---------------- */
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const upload = multer({ storage: multer.memoryStorage() });

/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// FORCE HTTPS in Production
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

// 1. Send Welcome Notification
async function sendWelcomeNote(userId) {
  try {
    await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, 1, $2)", 
    [userId, "Welcome to Apugo Village! 🌴"]);
  } catch (err) { console.error("Notification Error:", err); }
}

// 2. Admin Only Gatekeeper
function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') return next();
  req.flash("error", "Access denied. Elders only!");
  res.redirect("/feed");
}

// 3. Verified Only Gatekeeper
function isVerified(req, res, next) {
  if (req.isAuthenticated() && req.user.is_verified) return next();
  req.flash("error", "Please verify your email to interact with the village.");
  res.redirect("/profile");
}

// 4. Global Template Variables & Activity Tracker
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

/* ---------------- PASSPORT STRATEGIES ---------------- */

passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email=$1", [email]);
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
    const email = profile.emails[0].value;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) return done(null, result.rows[0]);
    
    // Google users are automatically verified
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

// --- Authentication ---
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
    const user = await db.query("INSERT INTO users (email, password, role) VALUES ($1,$2,$3) RETURNING *", [email, hash, "user"]);
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
app.get("/logout", (req, res) => req.logout(() => res.redirect("/")));

// --- Admin Dashboard ---
app.get("/admin", isAdmin, async (req, res) => {
  try {
    const usersCount = await db.query("SELECT COUNT(*) FROM users");
    const postsCount = await db.query("SELECT COUNT(*) FROM events WHERE is_deleted = false");
    const recentActivity = await db.query(`
      SELECT e.*, u.email as author_email 
      FROM events e 
      JOIN users u ON e.created_by = u.id 
      WHERE is_deleted = false 
      ORDER BY created_at DESC LIMIT 10
    `);
    res.render("admin-dashboard", { 
      stats: { users: usersCount.rows[0].count, posts: postsCount.rows[0].count },
      recentPosts: recentActivity.rows,
      search: "" 
    });
  } catch (err) { res.status(500).send("Admin access error"); }
});

// --- Feed & Posts ---
app.get("/feed", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const search = req.query.search || "";
  try {
    const announcements = await db.query(`SELECT e.*, u.email AS author FROM events e JOIN users u ON e.created_by=u.id WHERE is_announcement=true AND is_deleted=false ORDER BY created_at DESC`);
    const trending = await db.query(`SELECT e.id, e.description, COUNT(l.id) as likes_count FROM events e LEFT JOIN likes l ON e.id = l.event_id WHERE e.is_deleted = false GROUP BY e.id ORDER BY likes_count DESC LIMIT 3`);
    
    let postsQuery = `
      SELECT e.*, u.email AS author, u.last_active, u.is_verified, 
      (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes,
      (SELECT JSON_AGG(json_build_object('content', c.content, 'author', cu.email)) FROM comments c JOIN users cu ON c.user_id = cu.id WHERE c.event_id = e.id) as comments_list
      FROM events e JOIN users u ON e.created_by=u.id 
      WHERE is_announcement=false AND is_deleted=false
    `;
    
    const params = [];
    if (search) { 
      postsQuery += ` AND (e.description ILIKE $1)`; 
      params.push(`%${search}%`); 
    }
    postsQuery += ` ORDER BY e.is_pinned DESC, e.created_at DESC`;
    
    const posts = await db.query(postsQuery, params);
    res.render("feed", { announcements: announcements.rows, posts: posts.rows, trending: trending.rows, search });
  } catch (err) { res.status(500).send("Error loading feed"); }
});

// --- Post Creation (Supabase) ---
app.post("/event/create", isVerified, upload.single("localMedia"), async (req, res) => {
  try {
    let mediaUrl = null;
    let mediaType = 'image';

    if (req.file) {
      const fileName = `${Date.now()}-${req.file.originalname}`;
      await supabase.storage.from('apugo_village').upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: true
      });
      const { data: publicData } = supabase.storage.from('apugo_village').getPublicUrl(fileName);
      mediaUrl = publicData.publicUrl;
      mediaType = req.file.mimetype.startsWith("video") ? 'video' : 'image';
    }

    await db.query(
      "INSERT INTO events (title, description, image_url, created_by, is_announcement, media_type) VALUES ($1,$2,$3,$4,$5,$6)", 
      ["Post", req.body.description, mediaUrl, req.user.id, req.user.role === 'admin', mediaType]
    );
    res.redirect("/feed");
  } catch (err) { res.redirect("/feed"); }
});

// --- Likes, Comments, Delete ---
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
    await db.query("INSERT INTO comments (event_id, user_id, content) VALUES ($1, $2, $3)", [req.params.id, req.user.id, req.body.content]);
    res.redirect("back");
  } catch (err) { res.redirect("back"); }
});

app.post("/event/:id/delete", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    await db.query(`
      UPDATE events 
      SET is_deleted = true 
      WHERE id = $1 AND (created_by = $2 OR (SELECT role FROM users WHERE id = $2) = 'admin')
    `, [req.params.id, req.user.id]);
    res.redirect("back");
  } catch (err) { res.redirect("back"); }
});

// --- Settings & Profile ---
app.get("/settings", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.render("settings", { user: req.user, search: "" });
});

app.post("/settings/update", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const { email, newPassword } = req.body;
  try {
    await db.query("UPDATE users SET email = $1 WHERE id = $2", [email, req.user.id]);
    if (newPassword && newPassword.trim() !== "") {
      const hash = await bcrypt.hash(newPassword, saltRounds);
      await db.query("UPDATE users SET password = $1 WHERE id = $2", [hash, req.user.id]);
    }
    req.flash("success", "Settings updated!");
    res.redirect("/settings");
  } catch (err) { res.redirect("/settings"); }
});

app.get("/profile", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const result = await db.query("SELECT * FROM events WHERE created_by = $1 AND is_deleted = false ORDER BY created_at DESC", [req.user.id]);
    res.render("profile", { posts: result.rows, search: "" });
  } catch (e) { res.redirect("/feed"); }
});

// --- Password Reset ---
app.get("/forgot-password", (req, res) => res.render("forgot-password", { search: "" }));

app.post("/auth/reset-password", async (req, res) => {
  const { email } = req.body;
  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.SITE_URL || 'http://localhost:3000'}/update-password`,
    });
    if (error) throw error;
    req.flash("success", "Reset link sent! Check your email.");
    res.redirect("/login");
  } catch (err) { res.redirect("/forgot-password"); }
});

app.get("/update-password", (req, res) => res.render("update-password", { search: "" }));

app.post("/auth/update-password", async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const hash = await bcrypt.hash(newPassword, saltRounds);
    // Password update also verifies the user
    await db.query("UPDATE users SET password = $1, is_verified = true WHERE email = $2", [hash, email]);
    req.flash("success", "Password updated successfully!");
    res.redirect("/login");
  } catch (err) { res.redirect("/update-password"); }
});

// --- Notifications API ---
app.get("/api/notifications", async (req, res) => {
  if (!req.isAuthenticated()) return res.json([]);
  try {
    const result = await db.query("SELECT * FROM notifications WHERE user_id = $1 AND is_read = false", [req.user.id]);
    await db.query("UPDATE notifications SET is_read = true WHERE user_id = $1", [req.user.id]);
    res.json(result.rows);
  } catch (e) { res.json([]); }
});

app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));