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

/* ---------------- DATABASE CONFIG ---------------- */
const db = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000,
});

db.on('error', (err) => console.error('🔥 Postgres Error:', err));

/* ---------------- SUPABASE & STORAGE ---------------- */
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } 
});

/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1);
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(session({
    store: new PostgresStore({ pool: db, tableName: 'session', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || "apugo_village_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24 * 7,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? 'none' : 'lax'
    }
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

/* ---------------- GLOBAL LOCALS & HELPERS ---------------- */

app.use(async (req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.messages = req.flash();
    res.locals.unreadCount = 0;
    res.locals.unreadChats = 0;

    if (req.isAuthenticated()) {
        try {
            // Update activity and get alert counts in one query
            const counts = await db.query(`
                WITH activity AS (UPDATE users SET last_active = NOW() WHERE id = $1),
                     notes AS (SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false),
                     chats AS (SELECT COUNT(*) FROM messages WHERE receiver_id = $1 AND is_read = false)
                SELECT notes.count as n_count, chats.count as c_count FROM notes, chats
            `, [req.user.id]);
            res.locals.unreadCount = counts.rows[0].n_count;
            res.locals.unreadChats = counts.rows[0].c_count;
        } catch (e) { console.error("Locals error:", e); }
    }
    next();
});

const ensureAuth = (req, res, next) => req.isAuthenticated() ? next() : res.redirect("/login");
const ensureAdmin = (req, res, next) => (req.isAuthenticated() && req.user.role === 'admin') ? next() : res.redirect("/feed");

async function notify(userId, senderId, msg) {
    try {
        await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)", [userId, senderId, msg]);
    } catch (e) { console.error("Notify failed"); }
}

/* ---------------- PASSPORT CONFIG ---------------- */

passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
        const res = await db.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
        if (!res.rows.length) return done(null, false, { message: "Villager not found." });
        const user = res.rows[0];
        if (user.password === "google-oauth") return done(null, false, { message: "Use Google Login" });
        return await bcrypt.compare(password, user.password) ? done(null, user) : done(null, false, { message: "Wrong password" });
    } catch (err) { done(err); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    const res = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, res.rows[0]);
});

/* ---------------- ROUTES ---------------- */

app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        const user = await db.query("INSERT INTO users (email, password, role, is_verified) VALUES ($1,$2,'user',true) RETURNING *", [email.toLowerCase(), hash]);
        await notify(user.rows[0].id, 1, "Welcome to Apugo Village! 🌴");
        req.login(user.rows[0], () => res.redirect("/feed"));
    } catch (e) { req.flash("error", "Email taken."); res.redirect("/register"); }
});

app.post("/login", passport.authenticate("local", { successRedirect: "/feed", failureRedirect: "/login", failureFlash: true }));

app.get("/logout", (req, res) => req.logout(() => res.redirect("/")));

/* ---------------- FEED & SOCIAL ---------------- */

app.get("/feed", ensureAuth, async (req, res) => {
    const search = req.query.search || "";
    try {
        const trending = await db.query(`
            SELECT e.id, e.description, COUNT(l.id) as likes FROM events e 
            LEFT JOIN likes l ON e.id = l.event_id 
            WHERE e.is_deleted = false GROUP BY e.id ORDER BY likes DESC LIMIT 3
        `);
        
        const posts = await db.query(`
            SELECT e.*, u.email as author, u.is_verified,
            (SELECT COUNT(*) FROM likes WHERE event_id = e.id) as likes_count,
            (SELECT EXISTS(SELECT 1 FROM likes WHERE event_id = e.id AND user_id = $1)) as liked_by_me,
            (SELECT JSON_AGG(c) FROM (
                SELECT c.*, cu.email as author FROM comments c 
                JOIN users cu ON c.user_id = cu.id 
                WHERE c.event_id = e.id ORDER BY c.created_at ASC
            ) c) as comments_list
            FROM events e JOIN users u ON e.created_by = u.id
            WHERE e.is_deleted = false AND (e.description ILIKE $2)
            ORDER BY e.is_pinned DESC, e.created_at DESC
        `, [req.user.id, `%${search}%`]);

        res.render("feed", { posts: posts.rows, trending: trending.rows, search });
    } catch (e) { res.status(500).send("Village square is temporarily closed."); }
});

app.post("/event/create", ensureAuth, upload.single("localMedia"), async (req, res) => {
    try {
        let mediaUrl = null, mediaType = 'image';
        if (req.file) {
            const fileName = `post-${Date.now()}`;
            await supabase.storage.from('apugo_village').upload(fileName, req.file.buffer, { contentType: req.file.mimetype });
            mediaUrl = supabase.storage.from('apugo_village').getPublicUrl(fileName).data.publicUrl;
            mediaType = req.file.mimetype.startsWith("video") ? 'video' : 'image';
        }
        await db.query("INSERT INTO events (description, image_url, media_type, created_by) VALUES ($1,$2,$3,$4)", 
            [req.body.description, mediaUrl, mediaType, req.user.id]);
        res.redirect("/feed");
    } catch (e) { res.redirect("/feed"); }
});

app.post("/event/:id/like", ensureAuth, async (req, res) => {
    const check = await db.query("SELECT * FROM likes WHERE user_id=$1 AND event_id=$2", [req.user.id, req.params.id]);
    if (check.rows.length) {
        await db.query("DELETE FROM likes WHERE user_id=$1 AND event_id=$2", [req.user.id, req.params.id]);
    } else {
        await db.query("INSERT INTO likes (user_id, event_id) VALUES ($1,$2)", [req.user.id, req.params.id]);
    }
    res.redirect("back");
});

app.post("/event/:id/comment", ensureAuth, async (req, res) => {
    await db.query("INSERT INTO comments (event_id, user_id, content) VALUES ($1, $2, $3)", [req.params.id, req.user.id, req.body.content]);
    res.redirect("back");
});

/* ---------------- MESSAGING & FRIENDS ---------------- */

app.get("/messages", ensureAuth, async (req, res) => {
    const friends = await db.query(`
        SELECT u.id, u.email FROM users u
        JOIN friendships f ON (f.sender_id = u.id OR f.receiver_id = u.id)
        WHERE (f.sender_id = $1 OR f.receiver_id = $1) AND u.id != $1 AND f.status = 'accepted'
    `, [req.user.id]);
    res.render("messages", { friends: friends.rows });
});

app.get("/api/chat/:friendId", ensureAuth, async (req, res) => {
    const result = await db.query(`
        SELECT * FROM messages WHERE (sender_id = $1 AND receiver_id = $2) 
        OR (sender_id = $2 AND receiver_id = $1) ORDER BY created_at ASC
    `, [req.user.id, req.params.friendId]);
    await db.query("UPDATE messages SET is_read = true WHERE sender_id = $1 AND receiver_id = $2", [req.params.friendId, req.user.id]);
    res.json(result.rows);
});

app.post("/api/chat/send", ensureAuth, async (req, res) => {
    const { receiverId, content } = req.body;
    const msg = await db.query("INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING *", [req.user.id, receiverId, content]);
    res.json(msg.rows[0]);
});

/* ---------------- NOTIFICATIONS & ADMIN ---------------- */

app.get("/notifications", ensureAuth, async (req, res) => {
    const notes = await db.query(`
        SELECT n.*, u.email as sender_name FROM notifications n 
        JOIN users u ON n.sender_id = u.id WHERE n.user_id = $1 ORDER BY n.created_at DESC
    `, [req.user.id]);
    await db.query("UPDATE notifications SET is_read = true WHERE user_id = $1", [req.user.id]);
    res.render("notifications", { notes: notes.rows });
});

app.get("/admin", ensureAdmin, async (req, res) => {
    const users = await db.query("SELECT id, email, role, is_verified FROM users ORDER BY created_at DESC");
    res.render("admin-dashboard", { users: users.rows });
});

app.post("/admin/event/:id/delete", ensureAdmin, async (req, res) => {
    await db.query("UPDATE events SET is_deleted = true WHERE id = $1", [req.params.id]);
    res.redirect("back");
});

app.listen(port, () => console.log(`🚀 Village live on port ${port}`));