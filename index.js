import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import flash from "connect-flash";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { v2 as cloudinary } from 'cloudinary';
import pkg from 'multer-storage-cloudinary';

const CloudinaryStorage = pkg.CloudinaryStorage || pkg;

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

/* ---------------- DATABASE CONNECTION ---------------- */
const dbConfigs = {
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT || 5000,
};

if (process.env.DATABASE_URL) {
  dbConfigs.connectionString = process.env.DATABASE_URL;
}

if (process.env.DATABASE_URL || (process.env.PG_HOST && !process.env.PG_HOST.includes("localhost"))) {
  dbConfigs.ssl = { rejectUnauthorized: false };
}

const db = new pg.Client(dbConfigs);

try {
  await db.connect();
  console.log(`✅ Village DB connected on port ${dbConfigs.port}`);
} catch (err) {
  console.error("❌ Database connection error:", err.message);
}

/* ---------------- CLOUDINARY CONFIG ---------------- */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'apugo_village',
    resource_type: 'auto',
    allowed_formats: ['jpg', 'png', 'jpeg', 'mp4', 'mov']
  },
});
const upload = multer({ storage: storage });

/* ---------------- MIDDLEWARE ---------------- */
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(session({
  secret: process.env.SESSION_SECRET || "apugo_secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// FIX: Corrected parameters (was missing $2)
async function sendWelcomeNote(userId) {
  try {
    const note = "Welcome to Apugo Village! 🌴 Check the Discover tab to see what's trending.";
    // We use sender_id = 1 (System Admin)
    await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)", [userId, 1, note]);
  } catch (err) { console.error("Welcome Note Error:", err); }
}

// Global Variables middleware
app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.messages = req.flash();
  
  if (req.isAuthenticated()) {
    try {
      await db.query("UPDATE users SET last_active = NOW() WHERE id = $1", [req.user.id]);
      const noteCount = await db.query("SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false", [req.user.id]);
      res.locals.unreadCount = noteCount.rows[0].count;
    } catch (e) { 
      res.locals.unreadCount = 0; 
    }
  } else {
    res.locals.unreadCount = 0;
  }
  next();
});

/* ---------------- PASSPORT STRATEGIES ---------------- */
passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!result.rows.length) return done(null, false, { message: "User not found" });
    const user = result.rows[0];
    if (user.password === "google-oauth") return done(null, false, { message: "Please use Google Sign-In" });
    const valid = await bcrypt.compare(password, user.password);
    return valid ? done(null, user) : done(null, false, { message: "Wrong password" });
  } catch (err) { done(err); }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback"
}, async (token, secret, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) return done(null, result.rows[0]);
    
    const newUser = await db.query("INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING *", [email, "google-oauth", "user"]);
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

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => res.redirect("/feed"));

app.post("/register", async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, saltRounds);
    const user = await db.query("INSERT INTO users (email, password, role) VALUES ($1,$2,$3) RETURNING *", [req.body.email, hash, "user"]);
    await sendWelcomeNote(user.rows[0].id);
    req.login(user.rows[0], () => res.redirect("/feed"));
  } catch { res.redirect("/register"); }
});

app.post("/login", passport.authenticate("local", { successRedirect: "/feed", failureRedirect: "/login", failureFlash: true }));
app.get("/logout", (req, res) => req.logout(() => res.redirect("/")));

/* ---------------- FEED, DISCOVER & PROFILE ---------------- */
app.get("/feed", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const search = req.query.search || "";
  try {
    const announcements = await db.query(`SELECT e.*, u.email AS author FROM events e JOIN users u ON e.created_by=u.id WHERE is_announcement=true AND is_deleted=false ORDER BY created_at DESC`);
    const trending = await db.query(`SELECT e.id, e.description, COUNT(l.id) as likes_count FROM events e LEFT JOIN likes l ON e.id = l.event_id WHERE e.is_deleted = false GROUP BY e.id ORDER BY likes_count DESC LIMIT 3`);

    let postsQuery = `
      SELECT e.*, u.email AS author, (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes,
      (SELECT JSON_AGG(json_build_object('content', c.content, 'author', cu.email)) FROM comments c JOIN users cu ON c.user_id = cu.id WHERE c.event_id = e.id) as comments_list
      FROM events e JOIN users u ON e.created_by=u.id 
      WHERE is_announcement=false AND is_deleted=false
    `;
    const params = [];
    if (search) { postsQuery += ` AND (e.description ILIKE $1)`; params.push(`%${search}%`); }
    postsQuery += ` ORDER BY e.is_pinned DESC, e.created_at DESC`;

    const posts = await db.query(postsQuery, params);
    res.render("feed", { announcements: announcements.rows, posts: posts.rows, trending: trending.rows, search });
  } catch (err) { res.status(500).send("Error loading feed"); }
});

app.get("/discover", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const result = await db.query(`
      SELECT e.*, u.email AS author, (SELECT COUNT(*) FROM likes WHERE event_id=e.id) as likes_count
      FROM events e JOIN users u ON e.created_by = u.id
      WHERE is_deleted = false ORDER BY likes_count DESC, created_at DESC LIMIT 20
    `);
    res.render("discover", { posts: result.rows });
  } catch (e) { res.redirect("/feed"); }
});

// ADDED: Profile Route
app.get("/profile", async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");
    try {
        const userPosts = await db.query(
            "SELECT * FROM events WHERE created_by = $1 AND is_deleted = false ORDER BY created_at DESC",
            [req.user.id]
        );
        res.render("profile", { posts: userPosts.rows });
    } catch (err) {
        res.redirect("/feed");
    }
});

/* ---------------- ADMIN ---------------- */
app.get("/admin", async (req, res) => {
  if (!req.isAuthenticated() || req.user.role !== 'admin') return res.status(403).send("Admin access only.");
  const posts = await db.query("SELECT e.*, u.email as author FROM events e JOIN users u ON e.created_by = u.id WHERE is_deleted = false ORDER BY created_at DESC");
  const usersCount = await db.query("SELECT COUNT(*) FROM users");
  res.render("admin", { allPosts: posts.rows, totalUsers: usersCount.rows[0].count });
});

app.post("/event/:id/pin", async (req, res) => {
  if (req.user?.role === 'admin') {
    await db.query("UPDATE events SET is_pinned = NOT is_pinned WHERE id = $1", [req.params.id]);
  }
  res.redirect("back");
});

/* ---------------- ACTIONS ---------------- */
app.post("/event/create", upload.single("localMedia"), async (req, res) => {
  const mediaPath = req.file ? req.file.path : null;
  // Safer mimetype check
  const mediaType = (req.file && req.file.mimetype && req.file.mimetype.startsWith("video")) ? 'video' : 'image';
  
  await db.query("INSERT INTO events (title, description, image_url, created_by, is_announcement, media_type) VALUES ($1,$2,$3,$4,$5,$6)", 
    [req.body.title || "Post", req.body.description, mediaPath, req.user.id, req.user.role === 'admin', mediaType]);
  res.redirect("/feed");
});

app.post("/event/:id/like", async (req, res) => {
  const check = await db.query("SELECT * FROM likes WHERE user_id=$1 AND event_id=$2", [req.user.id, req.params.id]);
  if (check.rows.length) {
    await db.query("DELETE FROM likes WHERE user_id=$1 AND event_id=$2", [req.user.id, req.params.id]);
  } else {
    await db.query("INSERT INTO likes (user_id,event_id) VALUES ($1,$2)", [req.user.id, req.params.id]);
    const post = await db.query("SELECT created_by FROM events WHERE id=$1", [req.params.id]);
    if (post.rows[0].created_by !== req.user.id) {
      await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)", [post.rows[0].created_by, req.user.id, "Someone liked your post!"]);
    }
  }
  res.redirect("back");
});

app.post("/event/:id/comment", async (req, res) => {
  await db.query("INSERT INTO comments (event_id, user_id, content) VALUES ($1, $2, $3)", [req.params.id, req.user.id, req.body.content]);
  res.redirect("back");
});

app.post("/event/:id/delete", async (req, res) => {
  const result = await db.query("SELECT created_by FROM events WHERE id = $1", [req.params.id]);
  if (result.rows.length > 0 && (req.user.id === result.rows[0].created_by || req.user.role === 'admin')) {
    await db.query("UPDATE events SET is_deleted = true WHERE id = $1", [req.params.id]);
  }
  res.redirect("back");
});

app.listen(port, () => console.log(`🚀 Village Square open at http://localhost:${port}`));