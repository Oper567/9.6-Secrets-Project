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
import nodemailer from "nodemailer";

dotenv.config();

/* ---------------- INITIAL SETUP ---------------- */
const PostgresStore = pgSession(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

/* ---------------- SERVICES (DB, SUPABASE, MAIL) ---------------- */
const db = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000,
    max: 10,
});

db.on('error', (err) => console.error('Unexpected error on idle client', err));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // Increased to 5MB for village media
});

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
        createTableIfMissing: true
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

// Global Locals & Activity Tracker
app.use(async (req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.messages = req.flash();
    res.locals.unreadCount = 0;
    res.locals.search = ""; 

    if (req.isAuthenticated()) {
        try {
            await db.query("UPDATE users SET last_active = NOW() WHERE id = $1", [req.user.id]);
            const noteCount = await db.query("SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false", [req.user.id]);
            res.locals.unreadCount = noteCount.rows[0].count;
        } catch (e) { console.error("Middleware DB Error:", e); }
    }
    next();
});

/* ---------------- AUTHENTICATION HELPERS ---------------- */
function isAuth(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect("/login");
}

function checkVerified(req, res, next) {
    if (req.isAuthenticated()) {
        if (req.user.is_verified) return next();
        return res.render("verify-email-notice", { email: req.user.email });
    }
    res.redirect("/login");
}

function isAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') return next();
    req.flash("error", "Access denied. Elders only!");
    res.redirect("/feed");
}

async function sendWelcomeNote(userId) {
    try {
        await db.query("INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, 1, $2)",
            [userId, "Welcome to Apugo Village! 🌴"]);
    } catch (err) { console.error("Notification Error:", err); }
}

/* ---------------- PASSPORT STRATEGIES ---------------- */
passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
        if (!result.rows.length) return done(null, false, { message: "User not found" });

        const user = result.rows[0];
        if (!user.is_verified) return done(null, false, { message: "Please verify your email first." });
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

/* ---------------- AUTH ROUTES ---------------- */
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
        const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);

        const user = await db.query(
            "INSERT INTO users (email, password, role, is_verified, verification_token) VALUES ($1,$2,$3,$4,$5) RETURNING *",
            [email.toLowerCase(), hash, "user", false, token]
        );

        const verifyLink = `${req.protocol}://${req.get('host')}/auth/verify/${token}`;
        await transporter.sendMail({
            to: email.toLowerCase(),
            subject: "Verify your Apugo Village Account",
            html: `<p>Welcome! Click <a href="${verifyLink}">here</a> to verify your account.</p>`
        });

        await sendWelcomeNote(user.rows[0].id);
        res.render("verify-email-notice", { email: email.toLowerCase() });
    } catch (err) {
        req.flash("error", "Email already registered.");
        res.redirect("/register");
    }
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/feed",
    failureRedirect: "/login",
    failureFlash: true
}));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => res.redirect("/feed"));

app.get("/logout", (req, res) => {
    req.logout((err) => res.redirect("/"));
});

/* ---------------- VERIFICATION & PASSWORD RESET ---------------- */
app.get("/auth/verify/:token", async (req, res) => {
    const { token } = req.params;
    try {
        const result = await db.query(
            "UPDATE users SET is_verified = true, verification_token = NULL WHERE verification_token = $1 RETURNING *",
            [token]
        );
        if (result.rows.length > 0) {
            req.flash("success", "Village access granted! Sign in now.");
            res.redirect("/login");
        } else {
            res.status(400).send("Invalid or expired link.");
        }
    } catch (err) { res.redirect("/login"); }
});

app.get("/forgot-password", (req, res) => res.render("forgot-password", { message: null, error: null }));

app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const token = Math.random().toString(36).substring(2, 15);
        await db.query("UPDATE users SET reset_token = $1, reset_expires = NOW() + INTERVAL '1 hour' WHERE email = $2", [token, email.toLowerCase()]);
        
        const resetLink = `${req.protocol}://${req.get('host')}/reset-password/${token}`;
        await transporter.sendMail({
            to: email,
            subject: "Apugo Village Password Reset",
            text: `Reset your password here: ${resetLink}`
        });
        res.render("forgot-password", { message: "Reset link sent!", error: null });
    } catch (err) { res.render("forgot-password", { message: null, error: "System error." }); }
});

app.get("/reset-password/:token", async (req, res) => {
    res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        const result = await db.query(
            "UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE reset_token = $2 RETURNING *",
            [hash, token]
        );
        if (result.rows.length > 0) {
            req.flash("success", "Password updated!");
            res.redirect("/login");
        } else {
            res.status(400).send("Invalid token.");
        }
    } catch (err) { res.redirect("/login"); }
});

/* ---------------- FEED & EVENTS ---------------- */
app.get("/feed", checkVerified, async (req, res) => {
    const search = req.query.search || "";
    try {
        // 1. Fetch Announcements
        const announcements = await db.query(`
            SELECT e.*, u.email AS author FROM events e 
            JOIN users u ON e.created_by=u.id 
            WHERE is_announcement=true AND is_deleted=false 
            ORDER BY created_at DESC
        `);

        // 2. Fetch Trending
        const trending = await db.query(`
            SELECT e.id, e.description, COUNT(l.id) as likes_count 
            FROM events e LEFT JOIN likes l ON e.id = l.event_id 
            WHERE e.is_deleted = false 
            GROUP BY e.id ORDER BY likes_count DESC LIMIT 3
        `);
        
        // 3. Main Posts Query (Fixed the logic here)
        let postsQuery = `
            SELECT e.*, u.email AS author, u.profile_pic, u.is_verified,
            (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes_count,
            (SELECT EXISTS (SELECT 1 FROM likes WHERE event_id=e.id AND user_id=$1)) AS liked_by_me,
            (SELECT JSON_AGG(json_build_object(
                'id', c.id, 
                'content', c.content, 
                'author', cu.email, 
                'user_id', c.user_id
            )) FROM comments c JOIN users cu ON c.user_id = cu.id WHERE c.event_id = e.id) as comments_list
            FROM events e 
            JOIN users u ON e.created_by=u.id 
            WHERE is_announcement=false AND is_deleted=false
        `;
        
        const params = [req.user.id];

        if (search) { 
            postsQuery += ` AND (e.description ILIKE $2)`; 
            params.push(`%${search}%`); 
        }

        postsQuery += ` ORDER BY e.is_pinned DESC, e.created_at DESC`;
        
        const posts = await db.query(postsQuery, params);

        // 4. Render with ALL required locals
        res.render("feed", { 
            announcements: announcements.rows, 
            posts: posts.rows, 
            trending: trending.rows,
            search: search,
            unreadCount: res.locals.unreadCount,
            user: req.user
        });

    } catch (err) { 
        console.error("FEED ERROR:", err);
        res.status(500).send("Village Feed Error: " + err.message); 
    }
});
       

// ADD THIS: Discover Route (Random media gallery)
app.get("/discover", checkVerified, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT e.*, u.email as author 
            FROM events e 
            JOIN users u ON e.created_by = u.id 
            WHERE e.image_url IS NOT NULL AND e.is_deleted = false 
            ORDER BY RANDOM() LIMIT 24
        `);
        res.render("discover", { posts: result.rows });
    } catch (err) { res.redirect("/feed"); }
});

// ADD THIS: Single Post Detail Route
app.get("/event/:id", checkVerified, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT e.*, u.email AS author, u.profile_pic, u.is_verified,
            (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes_count,
            (SELECT JSON_AGG(json_build_object('content', c.content, 'author', cu.email, 'pic', cu.profile_pic)) 
             FROM comments c JOIN users cu ON c.user_id = cu.id 
             WHERE c.event_id = e.id ORDER BY c.created_at ASC) as comments_list
            FROM events e JOIN users u ON e.created_by=u.id 
            WHERE e.id = $1 AND e.is_deleted = false`, [req.params.id]);

        if (!result.rows.length) return res.status(404).send("Whisper not found.");
        res.render("event_detail", { post: result.rows[0] });
    } catch (err) { res.redirect("/feed"); }
});

app.post("/event/create", checkVerified, upload.single("localMedia"), async (req, res) => {
    try {
        let mediaUrl = null, mediaType = 'image';
        if (req.file) {
            const fileName = `${Date.now()}-${req.file.originalname}`;
            await supabase.storage.from('apugo_village').upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });
            mediaUrl = supabase.storage.from('apugo_village').getPublicUrl(fileName).data.publicUrl;
            mediaType = req.file.mimetype.startsWith("video") ? 'video' : 'image';
        }
        await db.query("INSERT INTO events (title, description, image_url, created_by, is_announcement, media_type) VALUES ($1,$2,$3,$4,$5,$6)", 
            ["Post", req.body.description, mediaUrl, req.user.id, req.user.role === 'admin', mediaType]);
        res.redirect("/feed");
    } catch (err) { res.redirect("/feed"); }
});

app.post("/event/:id/like", checkVerified, async (req, res) => {
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

app.post("/event/:id/comment", isAuth, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content || content.trim() === "") return res.redirect("back");

        await db.query(
            "INSERT INTO comments (event_id, user_id, content) VALUES ($1, $2, $3)", 
            [req.params.id, req.user.id, content]
        );
        
        res.redirect("back"); // This brings them right back to the feed
    } catch (err) { 
        console.error(err);
        res.redirect("back"); 
    }
});

app.post("/comment/:id/delete", isAuth, async (req, res) => {
    try {
        // Only allow owner or admin to delete
        const comment = await db.query("SELECT user_id FROM comments WHERE id = $1", [req.params.id]);
        
        if (comment.rows.length > 0 && (comment.rows[0].user_id === req.user.id || req.user.role === 'admin')) {
            await db.query("DELETE FROM comments WHERE id = $1", [req.params.id]);
        }
        res.redirect("back");
    } catch (err) {
        res.redirect("back");
    }
});

/* ---------------- CHAT SYSTEM ---------------- */
app.get("/messages", isAuth, async (req, res) => {
    try {
        // This query gets friends + their profile pic + if they were active in the last 5 mins + unread count
       const friends = await db.query(`
        SELECT 
        u.id, u.email, u.profile_pic,
        (u.last_active > NOW() - INTERVAL '5 minutes') as is_online
        FROM users u
        JOIN friendships f ON (f.sender_id = u.id OR f.receiver_id = u.id)
        WHERE (f.sender_id = $1 OR f.receiver_id = $1) 
        AND u.id != $1 
         AND f.status = 'accepted'`, [req.user.id]);

        res.render("messages", { 
            friends: friends.rows, 
            user: req.user 
        });
    } catch (err) { 
        console.error(err);
        res.redirect("/feed"); 
    }
});

/* ---------------- CHAT & KINSHIP CLEANUP ---------------- */

// 1. DELETE ALL MESSAGES (Burn Whispers)
// We use POST instead of DELETE for better compatibility with simple fetch calls
app.post("/api/chat/clear/:friendId", isAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        const friendId = req.params.friendId;

        // Deletes all messages exchanged between these two specific users
        await db.query(
            "DELETE FROM messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
            [userId, friendId]
        );

        res.json({ success: true, message: "Whispers burned." });
    } catch (err) {
        console.error("CLEAR CHAT ERROR:", err);
        res.status(500).json({ error: "The spirits failed to clear the history." });
    }
});

// 2. UNFRIEND (Break Kinship)
app.post("/api/friends/unfriend/:friendId", isAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        const friendId = req.params.friendId;

        // Removes the record from your 'friendships' table
        await db.query(
            "DELETE FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
            [userId, friendId]
        );

        res.json({ success: true, message: "Kinship broken." });
    } catch (err) {
        console.error("UNFRIEND ERROR:", err);
        res.status(500).json({ error: "Failed to break the bond." });
    }
});

app.post("/api/chat/send", isAuth, async (req, res) => {
    const { receiverId, content } = req.body;
    
    // Basic validation
    if (!content || !receiverId) {
        return res.status(400).json({ error: "Empty whisper or no recipient." });
    }

    try {
        const result = await db.query(
            "INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING *", 
            [req.user.id, receiverId, content]
        );
        
        // We MUST return the message as JSON so the frontend script can update the UI
        res.json(result.rows[0]);
    } catch (err) {
        console.error("SEND ERROR:", err);
        res.status(500).json({ error: "Whisper lost in the wind." });
    }
});

app.delete("/api/chat/clear/:friendId", isAuth, async (req, res) => {
    try {
        await db.query(
            "DELETE FROM messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)", 
            [req.user.id, req.params.friendId]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Burn failed" });
    }
});

/* ---------------- FRIENDSHIP SYSTEM ---------------- */
app.post("/friends/request/:id", isAuth, async (req, res) => {
    const senderId = req.user.id;
    const receiverId = req.params.id;

    if (parseInt(senderId) === parseInt(receiverId)) return res.redirect("/feed");

    try {
        // Change 'pending' to 'accepted' if you want immediate whispering
        const status = 'accepted'; 

        await db.query(
            "INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            [senderId, receiverId, status]
        );

        await db.query(
            "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)",
            [receiverId, senderId, "added you as kin!"]
        );
        
        res.redirect("/feed");
    } catch (err) {
        console.error("KINSHIP ERROR:", err);
        res.status(500).send("Error connecting souls.");
    }
});

app.post("/friends/accept/:senderId", isAuth, async (req, res) => {
    try {
        await db.query("UPDATE friendships SET status = 'accepted' WHERE sender_id = $1 AND receiver_id = $2", [req.params.senderId, req.user.id]);
        await db.query("INSERT INTO notifications (user_id, sender_id, actor_id, message) VALUES ($1, $2, $2, $3)", [req.params.senderId, req.user.id, "Accepted your friend request! 🌴"]);
        res.redirect("back");
    } catch (err) { res.redirect("back"); }
});

/* ---------------- PROFILE & SETTINGS ---------------- */
app.get('/profile', isAuth, async (req, res) => {
    try {
        const posts = await db.query('SELECT * FROM events WHERE created_by = $1 AND is_deleted = false ORDER BY created_at DESC', [req.user.id]);
        const friends = await db.query("SELECT COUNT(*) FROM friendships WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'accepted'", [req.user.id]);
        res.render('profile', { user: req.user, posts: posts.rows, friendCount: friends.rows[0].count });
    } catch (error) { res.status(500).send("Profile Error"); }
});

app.get("/notifications", isAuth, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT n.*, u.email as actor_name, u.profile_pic as actor_pic 
            FROM notifications n 
            LEFT JOIN users u ON n.actor_id = u.id 
            WHERE n.user_id = $1 
            ORDER BY n.created_at DESC LIMIT 50`, [req.user.id]);
        
        res.render("notifications", { notifications: result.rows });
    } catch (err) { res.redirect("/feed"); }
});

// ADD THIS: Clear Notifications Route
app.post("/notifications/clear", isAuth, async (req, res) => {
    try {
        // Use user_id (matches your middleware)
        await db.query("UPDATE notifications SET is_read = true WHERE user_id = $1", [req.user.id]);
        
        // This stops the infinite loading and refreshes the page
        res.redirect("/notifications"); 
    } catch (err) {
        console.error("NOTIFICATION CLEAR ERROR:", err);
        res.status(500).send("The spirits failed to clear the echoes.");
    }
});

app.get("/settings", isAuth, (req, res) => res.render("settings", { user: req.user }));

app.post("/settings/profile-pic", isAuth, upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file) return res.redirect("back");
        const dataUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
        await db.query("UPDATE users SET profile_pic = $1 WHERE id = $2", [dataUrl, req.user.id]);
        res.redirect("back");
    } catch (err) { res.redirect("back"); }
});

/* ---------------- SEARCH & ADMIN ---------------- */
app.get("/users/search", isAuth, async (req, res) => {
    try {
        const result = await db.query("SELECT id, email FROM users WHERE email ILIKE $1 AND id != $2 LIMIT 5", [`%${req.query.query}%`, req.user.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Search failed" }); }
});

app.post("/user/:id/follow", isAuth, async (req, res) => {
    const targetId = req.params.id;
    const followerId = req.user.id;

    if (targetId == followerId) return res.redirect("back");

    try {
        // Example logic for a simple follow (or reuse your friendship logic)
        await db.query(
            "INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, 'accepted') ON CONFLICT DO NOTHING", 
            [followerId, targetId]
        );
        res.redirect("back");
    } catch (err) {
        console.error(err);
        res.redirect("back");
    }
});

app.get("/admin", isAdmin, async (req, res) => {
    const users = await db.query("SELECT id, email, role, is_verified FROM users ORDER BY id DESC");
    res.render("admin-dashboard", { users: users.rows });
});

/* ---------------- SERVER START ---------------- */
app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));