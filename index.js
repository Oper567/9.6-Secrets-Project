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
// Configure multer to store files in memory temporarily
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 } // Limit: 2MB
});

db.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
/* ---------------- SUPABASE STORAGE & AUTH ---------------- */
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);


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

function checkVerified(req, res, next) {
    if (req.isAuthenticated() && req.user.is_verified) {
        return next();
    }
    // If logged in but not verified, show the notice
    if (req.isAuthenticated() && !req.user.is_verified) {
        return res.render("verify-email-notice", { email: req.user.email });
    }
    res.redirect("/login");
}

// Apply it to your routes
app.get("/feed", checkVerified, (req, res) => {
    // only verified users see this
});

/* ---------------- PASSPORT ---------------- */

passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (!result.rows.length) return done(null, false, { message: "User not found" });
    
    const user = result.rows[0];
    
    // Check if verified
    if (!user.is_verified) {
        return done(null, false, { message: "Please verify your email first." });
    }

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
        // 1. Generate a verification token
        const verificationToken = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
        
        // 2. Insert user with is_verified = false and store the token
        const user = await db.query(
            "INSERT INTO users (email, password, role, is_verified, verification_token) VALUES ($1,$2,$3,$4,$5) RETURNING *", 
            [email.toLowerCase(), hash, "user", false, verificationToken]
        );

        // 3. Send the Verification Email
        const verifyLink = `https://${req.get('host')}/auth/verify/${verificationToken}`;
        await transporter.sendMail({
            to: email.toLowerCase(),
            subject: "Verify your Apugo Village Account",
            html: `
                <div style="font-family: sans-serif; text-align: center; padding: 20px;">
                    <h2>Welcome to the Village!</h2>
                    <p>Click the button below to verify your email and join the square.</p>
                    <a href="${verifyLink}" style="background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Verify Email</a>
                    <p style="margin-top: 20px; color: #64748b; font-size: 12px;">If you didn't request this, please ignore this email.</p>
                </div>
            `
        });

        await sendWelcomeNote(user.rows[0].id);

        // 4. Redirect to a "Check your email" page instead of feeding them in
        res.render("verify-email-notice", { email: email.toLowerCase() });

    } catch (err) { 
        console.error(err);
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
// 1. The Verification Route
app.get("/verify", async (req, res) => {
    const { token } = req.query;

    try {
        const result = await db.query(
            "UPDATE users SET is_verified = true, verification_token = NULL WHERE verification_token = $1 RETURNING *",
            [token]
        );

        if (result.rows.length > 0) {
            // Success!
            res.render("login", { message: "Account verified! You can now login." });
        } else {
            res.status(400).send("Invalid or expired token.");
        }
    } catch (err) {
        console.error(err);
        res.redirect("/register");
    }
});

app.get("/users/search", async (req, res) => {
    const { query } = req.query;
    try {
        const result = await db.query(
            "SELECT id, email FROM users WHERE email ILIKE $1 AND id != $2 LIMIT 5",
            [`%${query}%`, req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Search failed" });
    }
});

app.get("/forgot-password", (req, res) => {
    res.render("forgot-password", { message: null, error: null });
});

app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await db.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
        
        if (user.rows.length > 0) {
            // 1. Generate a temporary reset token
            const resetToken = Math.random().toString(36).substring(2, 15);
            
            // 2. Save token to DB with an expiry (optional but recommended)
            await db.query("UPDATE users SET verification_token = $1 WHERE email = $2", [resetToken, email.toLowerCase()]);

            // 3. Send Email (Replace with your actual nodemailer transport)
            const resetLink = `https://${req.get('host')}/reset-password/${resetToken}`;
            // await transporter.sendMail({ ... }); 
            
            console.log("Reset Link:", resetLink); // For testing
        }

        // Always show success to prevent email fishing
        res.render("forgot-password", { 
            message: "If that email exists in our village, a reset link is on its way.", 
            error: null 
        });
    } catch (err) {
        res.render("forgot-password", { message: null, error: "Something went wrong." });
    }
});
// The Profile Picture Upload Route
app.post("/settings/profile-pic", upload.single("avatar"), async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");
    
    try {
        if (!req.file) {
            return res.redirect(req.get("Referrer") || "/feed");
        }

        // Convert the buffer to a Base64 string to store in the DB
        const base64Image = req.file.buffer.toString('base64');
        const dataUrl = `data:${req.file.mimetype};base64,${base64Image}`;

        await db.query(
            "UPDATE users SET profile_pic = $1 WHERE id = $2", 
            [dataUrl, req.user.id]
        );

        res.redirect(req.get("Referrer") || "/feed");
    } catch (err) {
        console.error("Upload Error:", err);
        res.redirect("/feed");
    }
});
app.post("/login", async (req, res) => {
    try {
        console.log("Login attempt for:", req.body.email); // Check if this shows in Render logs
        
        const { data, error } = await supabase.auth.signInWithPassword({
            email: req.body.email,
            password: req.body.password,
        });

        if (error) {
            console.log("Auth Error:", error.message);
            // This stops the spinner by sending the user back
            return res.render("login", { messages: { error: error.message } });
        }

        console.log("Success! Redirecting...");
        return res.redirect("/feed");

    } catch (err) {
        console.error("Critical System Error:", err);
        return res.status(500).send("The village gates are jammed. Try again later.");
    }
});

app.get("/auth/verify/:token", async (req, res) => {
    const { token } = req.params;
    try {
        const result = await db.query(
            "UPDATE users SET is_verified = true, verification_token = NULL WHERE verification_token = $1 RETURNING *",
            [token]
        );

        if (result.rows.length > 0) {
            req.flash("success", "Village access granted! You can now sign in.");
            res.redirect("/login");
        } else {
            res.status(400).send("Invalid or expired verification link.");
        }
    } catch (err) {
        console.error(err);
        res.redirect("/login");
    }
});

  // UNFRIEND: Remove connection and all related messages
  app.post("/friends/request/:id", async (req, res) => {
  if (!req.isAuthenticated() || req.user.id == req.params.id) {
      return res.redirect("/feed");
  }
  
  try {
    // Check if a request already exists to prevent duplicates
    const existing = await db.query(
        "SELECT * FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
        [req.user.id, req.params.id]
    );

    if (existing.rows.length === 0) {
        await db.query(
          "INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, 'pending')", 
          [req.user.id, req.params.id]
        );

        await db.query(
          "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)", 
          [req.params.id, req.user.id, "Sent you a village friend request! 🤝"]
        );
    }

    res.redirect("back");
  } catch (err) { 
    console.error(err);
    res.redirect("/feed"); 
  }
});
// DELETE ENTIRE CHAT HISTORY
app.post("/api/chat/delete/:friendId", async (req, res) => {
    await db.query(
        "DELETE FROM messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
        [req.user.id, req.params.friendId]
    );
    res.json({ success: true });
});

// ROUTE: Forgot Password
app.post("/auth/forgot-password", async (req, res) => {
    const token = Math.random().toString(36).substring(2);
    await db.query("UPDATE users SET reset_token = $1, reset_expires = NOW() + INTERVAL '1 hour' WHERE email = $2", [token, req.body.email]);
    
    const resetLink = `https://${req.get('host')}/reset-password/${token}`;
    await transporter.sendMail({
        to: req.body.email,
        subject: "Apugo Village Password Reset",
        text: `Click here to reset: ${resetLink}`
    });
    res.send("Reset link sent!");
});
// GET: Show the page where user types new password
app.get("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const result = await db.query(
        "SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()", 
        [token]
    );
    if (result.rows.length === 0) {
        req.flash("error", "Reset link is invalid or has expired.");
        return res.redirect("/login");
    }
    res.render("reset-password", { token }); // You'll need to create this EJS
});

// POST: Handle the new password submission
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
            req.flash("success", "Password updated! You can now login.");
            res.redirect("/login");
        } else {
            res.status(400).send("Invalid token.");
        }
    } catch (err) { res.redirect("/login"); }
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
    // This finds everyone who is 'accepted' with the current user
    const friends = await db.query(`
        SELECT u.id, u.email FROM users u
        JOIN friendships f ON (f.sender_id = u.id OR f.receiver_id = u.id)
        WHERE (f.sender_id = $1 OR f.receiver_id = $1) 
        AND u.id != $1 
        AND f.status = 'accepted'`, 
        [req.user.id]
    );
    
    res.render("messages", { 
        friends: friends.rows, 
        targetUser: req.query.userId || null, 
        search: "" 
    });
  } catch (err) { 
    console.error(err);
    res.redirect("/feed"); 
  }
});

app.get("/api/chat/:friendId", async (req, res) => {
    const { friendId } = req.params;
    const userId = req.user.id;

    try {
        // 1. Mark incoming messages as read
        await db.query(`
            UPDATE messages 
            SET is_read = true 
            WHERE sender_id = $1 AND receiver_id = $2 AND is_read = false
        `, [friendId, userId]);

        // 2. Fetch the conversation
        const result = await db.query(`
            SELECT * FROM messages 
            WHERE (sender_id = $1 AND receiver_id = $2)
               OR (sender_id = $2 AND receiver_id = $1)
            ORDER BY created_at ASC
        `, [userId, friendId]);

        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to sync whispers" });
    }
});

app.get("/users/search", async (req, res) => {
    const { name } = req.query;
    const result = await db.query(
        "SELECT id, email FROM users WHERE email ILIKE $1 LIMIT 10",
        [`%${name}%`]
    );
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
// GET Settings Page
app.get("/settings", async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");
    res.render("settings", { user: req.user, message: req.query.msg });
});

// POST Update Profile
app.post("/settings/update", async (req, res) => {
    const { bio, profile_pic } = req.body;
    try {
        await db.query(
            "UPDATE users SET bio = $1, profile_pic = $2 WHERE id = $3",
            [bio, profile_pic, req.user.id]
        );
        res.redirect("/settings?msg=Soul Updated");
    } catch (err) {
        res.redirect("/settings?msg=Update Failed");
    }
});

/* --- PROFILE & ADMIN --- */
app.get('/profile', async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");
    
    try {
        const userId = req.user.id;

        // 1. Fetch User Posts (Changed table name to 'events' and fixed $1 syntax)
        const postsResult = await db.query(
            'SELECT * FROM events WHERE created_by = $1 AND is_deleted = false ORDER BY created_at DESC', 
            [userId]
        );
        const posts = postsResult.rows;

        // 2. Fetch Kinship Count (Accepted Friends)
        const friendResult = await db.query(
            "SELECT COUNT(*) as count FROM friendships WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'accepted'", 
            [userId]
        );
        const friendCount = friendResult.rows[0].count;

        // 3. Fetch Unread Alerts Count
        const alertResult = await db.query(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = false', 
            [userId]
        );
        const unreadCount = alertResult.rows[0].count;

        res.render('profile', {
            user: req.user,
            posts: posts,
            friendCount: friendCount,
            unreadCount: unreadCount
        });

    } catch (error) {
        console.error("Critical Profile Error:", error);
        res.status(500).send(`Error loading profile: ${error.message}`);
    }
});
app.get("/notifications", async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");

    try {
        // 1. Get all notifications for the user
        // We JOIN with users to get the "actor's" profile picture and name
        const result = await db.query(`
            SELECT 
                n.*, 
                u.email as actor_name, 
                u.profile_pic as actor_pic 
            FROM notifications n
            JOIN users u ON n.actor_id = u.id
            WHERE n.user_id = $1
            ORDER BY n.created_at DESC
            LIMIT 50
        `, [req.user.id]);

        // 2. Mark them as read now that the user has seen them
        await db.query("UPDATE notifications SET is_read = true WHERE user_id = $1", [req.user.id]);

        res.render("notifications", { 
            user: req.user, 
            notifications: result.rows 
        });
    } catch (err) {
        console.error(err);
        res.redirect("/feed");
    }
});

app.get("/settings", (req, res) => req.isAuthenticated() ? res.render("settings", { user: req.user, search: "" }) : res.redirect("/login"));

app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await db.query("SELECT id, email, role, is_verified FROM users ORDER BY id DESC");
    res.render("admin-dashboard", { users: users.rows, search: "" });
  } catch (err) { res.redirect(req.get('Referrer') || '/feed'); }
});

app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));