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
import { createClient } from "@supabase/supabase-js";
import nodemailer from "nodemailer";
import { Resend } from "resend";
import pkg from "@prisma/client";
dotenv.config();

/* ---------------- INITIAL SETUP ---------------- */
const PostgresStore = pgSession(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { PrismaClient } = pkg;
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const router = express.Router();
const upload = multer({ dest: 'uploads/' });
const prisma = new PrismaClient({
  datasourceUrl: process.env.DATABASE_URL,
});

/* ---------------- SERVICES (DB, SUPABASE, MAIL) ---------------- */
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 10,
});

db.on("error", (err) => console.error("Unexpected error on idle client", err));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);
/* ---------------- MAIL SERVICE (RESEND) ---------------- */
const resend = new Resend(process.env.EMAIL_PASS);
// Verification Function
const sendVerificationEmail = async (toEmail, token) => {
  const mailOptions = {
    from: `"Apugo Village" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "Verify Your Apugo Account",
    html: `
            <div style="font-family: sans-serif; padding: 20px; color: #333;">
                <h2>Welcome to the Village!</h2>
                <p>Please verify your email to start whispering with your neighbors.</p>
                <a href="https://your-app-name.onrender.com/verify/${token}" 
                   style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                   Verify My Soul
                </a>
            </div>
        `,
  };

  return transporter.sendMail(mailOptions);
};
const mediaUrl = req.file ? `/uploads/${req.file.filename}` : null;

await db.query(`
    INSERT INTO forum_posts (title, content, category, author_id, media_url)
    VALUES ($1, $2, $3, $4, $5)
`, [title, content, category, userId, mediaUrl]);



/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
// HTTPS Redirect for Production
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === "production" &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    return res.redirect("https://" + req.get("host") + req.url);
  }
  next();
});

app.use(
  session({
    store: new PostgresStore({
      pool: db,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || "apugo_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    },
  })
);

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
      await db.query("UPDATE users SET last_active = NOW() WHERE id = $1", [
        req.user.id,
      ]);
      const noteCount = await db.query(
        "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false",
        [req.user.id]
      );
      res.locals.unreadCount = noteCount.rows[0].count;
    } catch (e) {
      console.error("Middleware DB Error:", e);
    }
  }
  next();
});

/* ---------------- AUTHENTICATION HELPERS ---------------- */
// Example of a safe isAuth middleware
function isAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  // Instead of goBack, send them to login
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
  if (req.isAuthenticated() && req.user.role === "admin") return next();
  req.flash("error", "Access denied. Elders only!");
  res.redirect("/feed");
}

async function sendWelcomeNote(userId) {
  try {
    await db.query(
      "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, 1, $2)",
      [userId, "Welcome to Apugo Village! 🌴"]
    );
  } catch (err) {
    console.error("Notification Error:", err);
  }
}

async function sendVibe(btn, postId) {
  // Add a quick "pop" animation locally for instant feedback
  btn.style.transform = "scale(1.3)";
  setTimeout(() => (btn.style.transform = "scale(1)"), 150);

  try {
    const response = await fetch(`/event/${postId}/like`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    const data = await response.json();

    if (data.success) {
      const icon = btn.querySelector("i");
      const countSpan = btn.querySelector(".vibe-count");

      // Update Count
      countSpan.innerText = data.newCount;

      // Toggle Visuals
      if (data.isLiked) {
        btn.classList.replace("text-slate-500", "text-red-500");
        icon.classList.replace("far", "fas");
      } else {
        btn.classList.replace("text-red-500", "text-slate-500");
        icon.classList.replace("fas", "far");
      }
    }
  } catch (err) {
    console.error("Vibe failed to travel:", err);
  }
}

/* ---------------- PASSPORT STRATEGIES ---------------- */
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email=$1", [
          email.toLowerCase(),
        ]);
        if (!result.rows.length)
          return done(null, false, { message: "User not found" });

        const user = result.rows[0];

        if (user.password === "google-oauth")
          return done(null, false, { message: "Use Google Sign-In" });

        const valid = await bcrypt.compare(password, user.password);
        return valid
          ? done(null, user)
          : done(null, false, { message: "Wrong password" });
      } catch (err) {
        done(err);
      }
    }
  )
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      proxy: true,
    },
    async (token, secret, profile, done) => {
      try {
        const email = profile.emails[0].value.toLowerCase();
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          email,
        ]);
        if (result.rows.length > 0) return done(null, result.rows[0]);

        const newUser = await db.query(
          "INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING *",
          [email, "google-oauth", "user", true]
        );
        await sendWelcomeNote(newUser.rows[0].id);
        return done(null, newUser.rows[0]);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, result.rows[0]);
  } catch (e) {
    done(e);
  }
});

/* ---------------- AUTH ROUTES ---------------- */
app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

/* ---------------- UPDATED REGISTER ROUTE ---------------- */
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);

    // We set is_verified to TRUE immediately
    await db.query(
      "INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4)",
      [email.toLowerCase(), hash, "user", true]
    );

    console.log(`✅ User ${email} registered and auto-verified.`);

    // Redirect straight to login or auto-login them
    req.flash("success", "Registration successful! Welcome to the village.");
    res.redirect("/login");
  } catch (err) {
    console.error("REGISTRATION ERROR:", err);
    req.flash("error", "Email already exists.");
    res.redirect("/register");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/feed",
    failureRedirect: "/login",
    failureFlash: true,
  })
);


app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => res.redirect("/feed")
);

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
      req.flash("success", "Soul verified! You may now enter the village.");
      res.redirect("/login");
    } else {
      res.status(400).send("This verification link has expired or is invalid.");
    }
  } catch (err) {
    console.error("Verification DB Error:", err);
    res.redirect("/login");
  }
});

app.get("/forgot-password", (req, res) =>
  res.render("forgot-password", { message: null, error: null })
);

/* ---------------- UPDATED FORGOT PASSWORD ROUTE ---------------- */
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const userCheck = await db.query("SELECT * FROM users WHERE email = $1", [
      email.toLowerCase(),
    ]);
    if (userCheck.rows.length === 0) {
      return res.render("forgot-password", {
        message: null,
        error: "Email not found.",
      });
    }

    const token = Math.random().toString(36).substring(2, 15);
    await db.query(
      "UPDATE users SET reset_token = $1, reset_expires = NOW() + INTERVAL '1 hour' WHERE email = $2",
      [token, email.toLowerCase()]
    );

    const resetLink = `${req.protocol}://${req.get(
      "host"
    )}/reset-password/${token}`;

    // USE THE API METHOD INSTEAD OF SMTP
    const { data, error } = await resend.emails.send({
      from: "Apugo <onboarding@resend.dev>",
      to: [email.toLowerCase()],
      subject: "Apugo Village | Password Reset",
      html: `<p>Reset your password here: <a href="${resetLink}">${resetLink}</a></p>`,
    });

    if (error) {
      console.error("Resend API Error:", error);
      throw new Error(error.message);
    }

    console.log("✅ API Email sent successfully:", data.id);
    res.render("forgot-password", { message: "Reset link sent!", error: null });
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err.message);
    res.render("forgot-password", {
      message: null,
      error: "The village spirits are blocked. Try again.",
    });
  }
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
  } catch (err) {
    res.redirect("/login");
  }
});

/* ---------------- FEED & EVENTS ---------------- */
app.get("/feed", checkVerified, async (req, res) => {
  const search = req.query.search || "";
  try {
    // 1. Fetch Announcements
    const announcements = await db.query(`
      SELECT e.*, u.email AS author FROM events e 
      JOIN users u ON e.created_by = u.id 
      WHERE is_announcement = true AND is_deleted = false 
      ORDER BY created_at DESC
    `);

    // 2. Fetch Trending
    const trending = await db.query(`
      SELECT e.id, e.description, COUNT(l.id) as likes_count 
      FROM events e LEFT JOIN likes l ON e.id = l.event_id 
      WHERE e.is_deleted = false 
      GROUP BY e.id ORDER BY likes_count DESC LIMIT 3
    `);

    // 3. Fetch Villagers (friends)
    let villagerParams = [req.user.id];
    let villagerSearchQuery = `SELECT id, email, profile_pic FROM users WHERE id != $1`;
    if (search) {
      villagerSearchQuery += ` AND email ILIKE $2`;
      villagerParams.push(`%${search}%`);
    }
    const suggestedUsers = await db.query(villagerSearchQuery + ` LIMIT 10`, villagerParams);

    // 4. Main Posts Query
    let params = [req.user.id];
    let postsQuery = `
      SELECT e.*, u.email AS author, u.profile_pic, u.is_verified,
      (SELECT COUNT(*) FROM likes WHERE event_id = e.id) AS likes_count,
      (SELECT EXISTS (SELECT 1 FROM likes WHERE event_id = e.id AND user_id = $1)) AS liked_by_me,
      (SELECT JSON_AGG(json_build_object(
          'id', c.id, 
          'comment_text', c.content, 
          'username', cu.email, 
          'user_id', c.user_id
      )) FROM comments c JOIN users cu ON c.user_id = cu.id WHERE c.event_id = e.id) as comments_list
      FROM events e 
      JOIN users u ON e.created_by = u.id 
      WHERE is_announcement = false AND is_deleted = false
    `;

    if (search) {
      postsQuery += ` AND (e.description ILIKE $2 OR u.email ILIKE $2)`;
      params.push(`%${search}%`);
    }

    postsQuery += ` ORDER BY e.is_pinned DESC, e.created_at DESC`;
    const posts = await db.query(postsQuery, params);

    // 5. Final Render
    res.render("feed", {
      announcements: announcements.rows,
      posts: posts.rows,
      trending: trending.rows,
      friends: suggestedUsers.rows, // Matched to your EJS variable name
      search: search,
      unreadCount: res.locals.unreadCount || 0,
      user: req.user,
    });

  } catch (err) {
    console.error("FEED ERROR:", err);
    res.status(500).send("Village Feed Error: " + err.message);
  }
});
function appendPostToFeed(p) {
  // ... (previous logic for post body)

  // Generate the HTML for existing comments on this post
  let commentsHTML = "";
  if (p.comments_list && p.comments_list.length > 0) {
    p.comments_list.forEach((c) => {
      commentsHTML += `
                <div class="flex items-start gap-3 mb-3">
                    <div class="w-7 h-7 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                        <span class="text-[10px] font-bold text-blue-400">${
                          c.username ? c.username.charAt(0).toUpperCase() : "?"
                        }</span>
                    </div>
                    <div class="bg-white/5 rounded-2xl p-3 flex-1">
                        <p class="text-[9px] font-black text-blue-400 uppercase">@${
                          c.username
                        }</p>
                        <p class="text-xs text-slate-300 mt-0.5">${
                          c.comment_text
                        }</p>
                    </div>
                </div>`;
    });
  } else {
    commentsHTML =
      '<p class="text-center text-[10px] text-slate-600 font-bold italic py-4">No echoes yet...</p>';
  }

  // Insert into the echoes div
  const echoesDiv = document.querySelector(`#echoes-${p.id} .p-6`);
  if (echoesDiv) echoesDiv.innerHTML = commentsHTML;
}

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
  } catch (err) {
    res.redirect("/feed");
  }
});

// ADD THIS: Single Post Detail Route
app.get("/event/:id", checkVerified, async (req, res) => {
  try {
    const result = await db.query(
      `
            SELECT e.*, u.email AS author, u.profile_pic, u.is_verified,
            (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes_count,
            (SELECT JSON_AGG(json_build_object('content', c.content, 'author', cu.email, 'pic', cu.profile_pic)) 
             FROM comments c JOIN users cu ON c.user_id = cu.id 
             WHERE c.event_id = e.id ORDER BY c.created_at ASC) as comments_list
            FROM events e JOIN users u ON e.created_by=u.id 
            WHERE e.id = $1 AND e.is_deleted = false`,
      [req.params.id]
    );

    if (!result.rows.length) return res.status(404).send("Whisper not found.");
    res.render("event_detail", { post: result.rows[0] });
  } catch (err) {
    res.redirect("/feed");
  }
});

app.post(
  "/event/create",
  checkVerified,
  upload.single("localMedia"),
  async (req, res) => {
    try {
      let mediaUrl = null,
        mediaType = "image";
      if (req.file) {
        const fileName = `${Date.now()}-${req.file.originalname}`;
        await supabase.storage
          .from("apugo_village")
          .upload(fileName, req.file.buffer, {
            contentType: req.file.mimetype,
            upsert: true,
          });
        mediaUrl = supabase.storage.from("apugo_village").getPublicUrl(fileName)
          .data.publicUrl;
        mediaType = req.file.mimetype.startsWith("video") ? "video" : "image";
      }
      await db.query(
        "INSERT INTO events (title, description, image_url, created_by, is_announcement, media_type) VALUES ($1,$2,$3,$4,$5,$6)",
        [
          "Post",
          req.body.description,
          mediaUrl,
          req.user.id,
          req.user.role === "admin",
          mediaType,
        ]
      );
      res.redirect("/feed");
    } catch (err) {
      res.redirect("/feed");
    }
  }
);
app.post("/event/:id/like", async (req, res) => {
  try {
    const postId = req.params.id;

    // 1. Logic to increment like count in your DB
    // 2. Fetch the new total
    const newCount = 10; // This would be the result from your DB

    res.json({ success: true, newCount: newCount });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});
// Ensure this is in your main file or the router linked to '/event'
app.post('/event/:id/delete', async (req, res) => {
    try {
        const { id } = req.params;
        // Verify user owns the post before deleting
        await db.query('DELETE FROM events WHERE id = $1 AND created_by = $2', [id, req.user.id]);
        res.redirect('/feed');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error deleting whisper");
    }
});
app.post('/event/create', upload.single('localMedia'), async (req, res) => {
    const { description } = req.body;
    // If you don't use upload.single(), 'description' will be UNDEFINED here.
    
    // ... your DB insert logic
    res.redirect('/feed');
});
app.post("/event/:id/report", async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id; // Assuming the user is logged in

  try {
    // Option A: Just log it in a 'reports' table (Recommended)
    await db.query(
      "INSERT INTO reports (post_id, reported_by, created_at) VALUES ($1, $2, NOW())",
      [postId, userId]
    );

    // Option B: Mark the post directly as 'under_review'
    // await db.query("UPDATE posts SET status = 'under_review' WHERE id = $1", [postId]);

    console.log(`⚠️ Post ${postId} was reported by user ${userId}`);

    req.flash(
      "success",
      "Thank you. The Village Elders will review this whisper."
    );
    res.redirect("/feed");
  } catch (err) {
    console.error("Report Error:", err);
    res.redirect("/feed");
  }
});
app.post("/event/:id/comment", async (req, res) => {
  try {
    const postId = parseInt(req.params.id); // Ensure ID is a number
    const { comment } = req.body;

    // Use the user ID from the session (adjust based on your auth)
    const userId = req.session.userId || 1;

    if (!comment) {
      return res.redirect("/feed");
    }

    // Save the comment using Prisma
    await prisma.comment.create({
      data: {
        comment_text: comment,
        post_id: postId,
        user_id: userId,
        // created_at is usually handled automatically by Prisma
      },
    });

    console.log(`Success: Echo saved on post ${postId}`);
    res.redirect("/feed");
  } catch (err) {
    console.error("Prisma Comment Error:", err);
    // Redirecting even on error prevents the 502/Infinite Loading screen
    res.redirect("/feed");
  }
});
app.post("/comment/:id/delete", isAuth, async (req, res) => {
  try {
    const comment = await db.query(
      "SELECT user_id FROM comments WHERE id = $1",
      [req.params.id]
    );
    if (
      comment.rows.length > 0 &&
      (comment.rows[0].user_id === req.user.id || req.user.role === "admin")
    ) {
      await db.query("DELETE FROM comments WHERE id = $1", [req.params.id]);
    }
    goBack(req, res); // FIX
  } catch (err) {
    goBack(req, res); // FIX
  }
});
// This crashes because 'req' doesn't exist here!
const activeCat = req.query.cat || 'all';
// 2. The route itself
// ... imports at the top ...

// 1. The route starts here
/* ---------------- FORUM ROUTES ---------------- */

// This is the "Container" that provides the 'req' and 'res' objects
// 1. THIS is the "building" (the route handler)
app.post("/forum/create", upload.single('media'), async (req, res) => {
    
    // 2. NOW 'req' is defined because a user just clicked 'submit'
    try {
        const mediaUrl = req.file ? `/uploads/${req.file.filename}` : null;
        const { title, content, category } = req.body;
        const userId = req.user.id;

        await db.query(`
            INSERT INTO forum_posts (title, content, category, author_id, media_url)
            VALUES ($1, $2, $3, $4, $5)
        `, [title, content, category, userId, mediaUrl]);

        res.redirect("/forum");
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});
/* ---------------- CHAT SYSTEM ---------------- */
app.get("/messages", isAuth, async (req, res) => {
  try {
    // This query gets friends + their profile pic + if they were active in the last 5 mins + unread count
    const friends = await db.query(
      `
        SELECT 
        u.id, u.email, u.profile_pic,
        (u.last_active > NOW() - INTERVAL '5 minutes') as is_online
        FROM users u
        JOIN friendships f ON (f.sender_id = u.id OR f.receiver_id = u.id)
        WHERE (f.sender_id = $1 OR f.receiver_id = $1) 
        AND u.id != $1 
         AND f.status = 'accepted'`,
      [req.user.id]
    );

    res.render("messages", {
      friends: friends.rows,
      user: req.user,
    });
  } catch (err) {
    console.error(err);
    res.redirect("/feed");
  }
});

app.get("/api/chat/:friendId", isAuth, async (req, res) => {
  const userId = req.user.id;
  const friendId = req.params.friendId;

  try {
    const result = await db.query(
      `SELECT 
                id, 
                sender_id, 
                receiver_id, 
                content AS content, -- Ensure this matches your DB column name
                created_at, 
                is_read 
             FROM messages 
             WHERE (sender_id = $1 AND receiver_id = $2) 
                OR (sender_id = $2 AND receiver_id = $1) 
             ORDER BY created_at ASC`,
      [userId, friendId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Ancient spirits blocked the message." });
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
// 1. CONNECT / REQUEST KINSHIP
app.post("/friends/request/:id", isAuth, async (req, res) => {
  const senderId = req.user.id;
  const receiverId = req.params.id;

  if (parseInt(senderId) === parseInt(receiverId)) return res.redirect("/feed");

  try {
    // We check if any relationship exists (either way)
    const check = await db.query(
      "SELECT * FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
      [senderId, receiverId]
    );

    if (check.rows.length === 0) {
      // Option A: Instant Friends (status='accepted')
      // Option B: Needs approval (status='pending')
      const status = "accepted";

      await db.query(
        "INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, $3)",
        [senderId, receiverId, status]
      );

      await db.query(
        "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)",
        [receiverId, senderId, "added you as kin!"]
      );
    }

    res.redirect(req.get("Referrer") || "/feed");
  } catch (err) {
    console.error("KINSHIP ERROR:", err);
    res.status(500).send("Error connecting souls.");
  }
});

// 2. SEVER KINSHIP (UNFRIEND)
app.post("/friends/unfriend/:id", isAuth, async (req, res) => {
  const targetId = req.params.id;
  const userId = req.user.id;
  try {
    // Matches the sender_id/receiver_id naming convention
    await db.query(
      "DELETE FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
      [userId, targetId]
    );
    res.redirect(req.get("Referrer") || "/feed");
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to sever kinship.");
  }
});

// FIX: Delete Chat (Assuming it deletes the message history between two users)
app.post("/messages/delete/:userId", checkVerified, async (req, res) => {
  const otherUserId = req.params.userId;
  const myId = req.user.id;
  try {
    await db.query(
      "DELETE FROM messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
      [myId, otherUserId]
    );
    res.redirect("/messages");
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to clear scrolls.");
  }
});

/* ---------------- PROFILE & SETTINGS ---------------- */
app.get("/profile", isAuth, async (req, res) => {
  try {
    const posts = await db.query(
      "SELECT * FROM events WHERE created_by = $1 AND is_deleted = false ORDER BY created_at DESC",
      [req.user.id]
    );
    const friends = await db.query(
      "SELECT COUNT(*) FROM friendships WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'accepted'",
      [req.user.id]
    );
    res.render("profile", {
      user: req.user,
      posts: posts.rows,
      friendCount: friends.rows[0].count,
    });
  } catch (error) {
    res.status(500).send("Profile Error");
  }
});

app.get("/notifications", isAuth, async (req, res) => {
  try {
    const result = await db.query(
      `
            SELECT n.*, u.email as actor_name, u.profile_pic as actor_pic 
            FROM notifications n 
            LEFT JOIN users u ON n.actor_id = u.id 
            WHERE n.user_id = $1 
            ORDER BY n.created_at DESC LIMIT 50`,
      [req.user.id]
    );

    res.render("notifications", { notifications: result.rows });
  } catch (err) {
    res.redirect("/feed");
  }
});

// ADD THIS: Clear Notifications Route
app.post("/notifications/clear", isAuth, async (req, res) => {
  try {
    // Use user_id (matches your middleware)
    await db.query(
      "UPDATE notifications SET is_read = true WHERE user_id = $1",
      [req.user.id]
    );

    // This stops the infinite loading and refreshes the page
    res.redirect("/notifications");
  } catch (err) {
    console.error("NOTIFICATION CLEAR ERROR:", err);
    res.status(500).send("The spirits failed to clear the echoes.");
  }
});

app.get("/settings", isAuth, (req, res) =>
  res.render("settings", { user: req.user })
);

app.post(
  "/settings/profile-pic",
  isAuth,
  upload.single("avatar"),
  async (req, res) => {
    try {
      if (!req.file) return res.redirect("back");
      const dataUrl = `data:${
        req.file.mimetype
      };base64,${req.file.buffer.toString("base64")}`;
      await db.query("UPDATE users SET profile_pic = $1 WHERE id = $2", [
        dataUrl,
        req.user.id,
      ]);
      res.redirect("back");
    } catch (err) {
      res.redirect("back");
    }
  }
);

/* ---------------- SEARCH & ADMIN ---------------- */
app.get("/users/search", isAuth, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, email FROM users WHERE email ILIKE $1 AND id != $2 LIMIT 5",
      [`%${req.query.query}%`, req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Search failed" });
  }
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
// VIEW ALL TOPICS
app.get("/forum", checkVerified, async (req, res) => {
  try {
    const result = await db.query(`
            SELECT t.*, u.email as author, 
            (SELECT COUNT(*) FROM forum_replies WHERE topic_id = t.id) as reply_count
            FROM forum_topics t
            JOIN users u ON t.creator_id = u.id
            ORDER BY t.created_at DESC
        `);
    res.render("forum", { topics: result.rows, user: req.user });
  } catch (err) {
    res.redirect("/feed");
  }
});

// CREATE NEW TOPIC
app.post("/forum/new", checkVerified, async (req, res) => {
  const { title, category } = req.body;
  await db.query(
    "INSERT INTO forum_topics (title, category, creator_id) VALUES ($1, $2, $3)",
    [title, category, req.user.id]
  );
  res.redirect("/forum");
});
// index.js or routes/forum.js

// This handles the form submission
// 1. THIS IS THE ROUTE (The "Local" scope)
// This is your "POST" route for creating a forum thread
app.post("/forum/create", upload.single('media'), async (req, res) => {
    try {
        // MOVE LINE 77 TO HERE (Inside the curly brace)
        const mediaUrl = req.file ? `/uploads/${req.file.filename}` : null;
        
        const { title, content, category } = req.body;
        const userId = req.user.id;

        await db.query(`
            INSERT INTO forum_posts (title, content, category, author_id, media_url)
            VALUES ($1, $2, $3, $4, $5)
        `, [title, content, category, userId, mediaUrl]);

        res.redirect("/forum");
    } catch (err) {
        console.error(err);
        res.status(500).send("The scroll could not be saved.");
    }
});




// Helper for "Time Ago"
function formatTimeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return date.toLocaleDateString();
}

app.get("/villagers", checkVerified, async (req, res) => {
  const search = req.query.search || "";
  try {
    const query = `
            SELECT u.id, u.email, u.profile_pic, u.is_verified,
            (SELECT status FROM friendships 
             WHERE (sender_id = $1 AND receiver_id = u.id) 
                OR (sender_id = u.id AND receiver_id = $1) 
             LIMIT 1) as friend_status
            FROM users u 
            WHERE u.id != $1 
            ${search ? "AND u.email ILIKE $2" : ""}
            ORDER BY u.is_verified DESC, u.email ASC`;

    const params = search ? [req.user.id, `%${search}%`] : [req.user.id];
    const result = await db.query(query, params);

    res.render("villagers", {
      villagers: result.rows,
      user: req.user,
      search: search,
    });
  } catch (err) {
    res.redirect("/feed");
  }
});
app.get("/admin", isAdmin, async (req, res) => {
  const users = await db.query(
    "SELECT id, email, role, is_verified FROM users ORDER BY id DESC"
  );
  res.render("admin-dashboard", { users: users.rows });
});

/* ---------------- SERVER START ---------------- */
app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));
