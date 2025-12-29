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
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { createClient } from "@supabase/supabase-js";
import nodemailer from "nodemailer";
import { Resend } from "resend";
import 'dotenv/config';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import pkg from 'multer-storage-cloudinary';
/* ---------------- DATABASE SETUP ---------------- */
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 2. NOW you can attach the error listener
db.on("error", (err) => console.error("Unexpected error on idle client", err));


// Handle the nested export in Node v22
const CloudinaryStorage = pkg.CloudinaryStorage || pkg.default?.CloudinaryStorage || pkg;

// Account Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// Setup Storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'village_square_media',
    resource_type: 'auto',
    allowed_formats: ['jpg', 'png', 'jpeg', 'gif', 'mp4', 'webp'],
  },
});

const upload = multer({ storage: storage });


// WRONG for Supabase: multer.diskStorage(...)
// 2. Configure Multer for Memory (Required for Supabase)



/* ---------------- INITIAL SETUP ---------------- */

const { PrismaClient } = pkg;
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const router = express.Router();
const PostgresStore = pgSession(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
/* 2. Second, define the specific folder path */
const uploadDir = path.join(__dirname, 'public/uploads');

/* 3. Now it is safe to check if it exists */
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Cloudinary Config


db.on("error", (err) => console.error("Unexpected error on idle client", err));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);
// ... after supabase.storage.from('apugo_village').upload(...)
// 1. Upload the file


// This finalImageUrl should be: 
// https://[YOUR_PROJECT].supabase.co/storage/v1/object/public/apugo_village/[FILENAME]
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





/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
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
// Add this at the VERY BOTTOM of index.js, after all your routes
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).send("File is too large! Max limit is 5MB.");
    }
  }
  res.status(500).send("An unknown error occurred.");
});

app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
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
// Protection middleware



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
  const userId = req.user.id; // Using current logged-in user ID

  try {
    // 1. Fetch Trending VIDEOS (Leaderboard)
    const trending = await db.query(`
      SELECT p.id, p.content, p.views_count, p.image_url
      FROM forum_posts p 
      WHERE p.is_deleted = false AND p.media_type = 'video'
      ORDER BY p.views_count DESC LIMIT 5
    `);

    // 2. Fetch Villagers (friends/suggested)
    let villagerParams = [userId];
    let villagerSearchQuery = `SELECT id, email, profile_pic FROM users WHERE id != $1`;
    if (search) {
      villagerSearchQuery += ` AND email ILIKE $2`;
      villagerParams.push(`%${search}%`);
    }
    const suggestedUsers = await db.query(villagerSearchQuery + ` LIMIT 10`, villagerParams);

    // 3. Main Posts Query
    let params = [userId];
    let postsQuery = `
      SELECT p.*, u.email AS author_email, u.profile_pic, u.is_verified,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
      (SELECT EXISTS (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = $1)) AS liked_by_me,
      (SELECT JSON_AGG(json_build_object(
          'username', split_part(cu.email, '@', 1), 
          'comment_text', r.reply_text, 
          'user_pic', cu.profile_pic
      )) FROM forum_replies r JOIN users cu ON r.author_id = cu.id WHERE r.post_id = p.id) as comments_list
      FROM forum_posts p 
      JOIN users u ON p.author_id = u.id 
      WHERE p.is_deleted = false
    `;

    if (search) {
      postsQuery += ` AND (p.content ILIKE $2 OR u.email ILIKE $2)`;
      params.push(`%${search}%`);
    }

    postsQuery += ` ORDER BY p.created_at DESC`;
    const posts = await db.query(postsQuery, params);

    // 4. Final Render
    res.render("feed", {
      posts: posts.rows,
      trending: trending.rows,
      friends: suggestedUsers.rows, // Matches the 'friends' variable in your EJS
      search: search,
      user: req.user,
      unreadCount: res.locals.unreadCount || 0
    });

  } catch (err) {
    console.error("FEED ERROR:", err);
    res.status(500).render("error", { message: "The village square is temporarily closed." });
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
app.get("/discover", isAuth, async (req, res) => {
    const searchQuery = req.query.search || "";
    const userId = req.user.id;

    try {
        let params = [];
        let sql = `
            SELECT p.*, u.email AS author, u.id AS created_by,
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes,
            (SELECT COUNT(*) FROM forum_replies WHERE post_id = p.id) AS comments_count
            FROM forum_posts p
            JOIN users u ON p.author_id = u.id
            WHERE p.is_deleted = false
        `;

        if (searchQuery) {
            sql += ` AND (p.content ILIKE $1 OR u.email ILIKE $1)`;
            params.push(`%${searchQuery}%`);
        }

        // Randomize for "Discover" feel, or order by most likes/views
        sql += ` ORDER BY RANDOM() LIMIT 20`;

        const result = await db.query(sql, params);

        res.render("discover", {
            posts: result.rows,
            user: req.user,
            search: searchQuery
        });
    } catch (err) {
        console.error("Discover Error:", err);
        res.status(500).send("The wilds are too misty to explore right now.");
    }
});

// ADD THIS: Single Post Detail Route


// Ensure this is in your main file or the router linked to '/event'
// POST: Toggle Like (Vibe)
app.post("/event/:id/like", isAuth, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;
  
  // 1. Declare the variable at the TOP of the scope
  let postAuthorId = null; 

  try {
    const postData = await db.query("SELECT author_id FROM forum_posts WHERE id = $1", [postId]);
    
    if (postData.rows.length === 0) {
      return res.json({ success: false, message: "Post vanished" });
    }

    // 2. Assign the value here
    postAuthorId = postData.rows[0].author_id;

    const existingLike = await db.query(
      "SELECT id FROM likes WHERE post_id = $1 AND user_id = $2",
      [postId, userId]
    );

    let isLiked;
    if (existingLike.rows.length > 0) {
      await db.query("DELETE FROM likes WHERE id = $1", [existingLike.rows[0].id]);
      isLiked = false;
    } else {
      await db.query("INSERT INTO likes (post_id, user_id) VALUES ($1, $2)", [postId, userId]);
      isLiked = true;

      // 3. This block now definitely knows what postAuthorId is
      if (postAuthorId && postAuthorId !== userId) {
        await db.query(
          "INSERT INTO notifications (user_id, sender_id, type, message) VALUES ($1, $2, $3, $4)",
          [postAuthorId, userId, 'like', 'admired your echo']
        );
      }
    }

    const countRes = await db.query("SELECT COUNT(*) FROM likes WHERE post_id = $1", [postId]);
    res.json({ success: true, isLiked, newCount: parseInt(countRes.rows[0].count) });

  } catch (err) {
    console.error("LIKE ERROR:", err);
    res.status(500).json({ success: false });
  }
});

app.post("/event/:id/view", isAuth, async (req, res) => {
    try {
        await db.query("UPDATE forum_posts SET views_count = views_count + 1 WHERE id = $1", [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});
// POST: Create a new Whisper (Forum Post)
app.post("/event/create", upload.single("localMedia"), async (req, res) => {
    const { description } = req.body;
    const authorId = req.user.id;
    
    let mediaUrl = null;
    let mediaType = 'image'; // Default

    if (req.file) {
        // This creates the URL /uploads/123456.mp4
        mediaUrl = `/uploads/${req.file.filename}`;
        
        // Detect if it's a video
        if (req.file.mimetype.startsWith('video/')) {
            mediaType = 'video';
        }
    }

    try {
        await db.query(
            `INSERT INTO forum_posts (author_id, title, content, image_url, media_type, created_at) 
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [authorId, description.substring(0, 20), description, mediaUrl, mediaType]
        );
        res.redirect("/feed");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error saving post.");
    }
});
app.post("/event/:id/report", checkVerified, async (req, res) => {
  const postId = req.params.id;
  const reporterId = req.user.id;
  const { reason } = req.body; // You can pass a reason from a prompt or modal

  try {
    await db.query(
      "INSERT INTO reports (post_id, reporter_id, reason) VALUES ($1, $2, $3)",
      [postId, reporterId, reason || "Unspecified"]
    );

    // Optional: If a post gets more than 5 reports, hide it automatically
    // await db.query("UPDATE forum_posts SET is_deleted = true WHERE id = $1 AND (SELECT COUNT(*) FROM reports WHERE post_id = $1) > 5", [postId]);

    res.json({ success: true, message: "Whisper reported to the elders." });
  } catch (err) {
    console.error("REPORT ERROR:", err);
    res.json({ success: false });
  }
});
// POST: Add an Echo (Reply)
app.post("/event/:id/comment", async (req, res) => {
  const { comment } = req.body;
  const postId = req.params.id;
  const authorId = req.user.id;

  if (!comment || comment.trim() === "") return res.json({ success: false });

  try {
    await db.query(
      `INSERT INTO forum_replies (post_id, author_id, reply_text, created_at) 
       VALUES ($1, $2, $3, NOW())`,
      [postId, authorId, comment]
    );

    res.json({ 
      success: true, 
      username: req.user.email.split('@')[0] 
    });
  } catch (err) {
    console.error("COMMENT ERROR:", err);
    res.json({ success: false });
  }
});
app.delete("/event/:postId/comment/:commentId", isAuth, async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user.id;

        // Check if comment exists and belongs to the user (or admin)
        const check = await db.query("SELECT user_id FROM comments WHERE id = $1", [commentId]);
        
        if (check.rows.length === 0) return res.json({ success: false, message: "Echo not found" });
        
        if (check.rows[0].user_id !== userId && req.user.role !== 'admin') {
            return res.json({ success: false, message: "Unauthorized" });
        }

        await db.query("DELETE FROM comments WHERE id = $1", [commentId]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});
app.post("/event/:id/delete", isAuth, async (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;

    try {
        // 1. Get the post data to find the image URL
        const postData = await db.query("SELECT image_url, author_id FROM forum_posts WHERE id = $1", [postId]);
        
        if (postData.rows.length === 0) return res.status(404).send("Post not found");
        
        const post = postData.rows[0];

        // 2. Security Check: Only the owner or an admin can delete
        if (post.author_id !== userId && req.user.role !== 'admin') {
            return res.status(403).send("Unauthorized");
        }

        // 3. IF there is an image, delete it from Cloudinary
        if (post.image_url) {
            // Extract public_id from the URL
            // Example URL: .../village_square/abc12345.jpg -> ID is 'village_square/abc12345'
            const parts = post.image_url.split('/');
            const fileName = parts[parts.length - 1].split('.')[0];
            const folderName = parts[parts.length - 2];
            const publicId = `${folderName}/${fileName}`;

            await cloudinary.uploader.destroy(publicId);
            console.log("Cloudinary asset deleted:", publicId);
        }

        // 4. Delete the post from the database
        await db.query("DELETE FROM forum_posts WHERE id = $1", [postId]);

        res.redirect("/feed");
    } catch (err) {
        console.error("DELETE ERROR:", err);
        res.status(500).send("Failed to delete post");
    }
});

app.delete("/event/:postId/comment/:commentId", isAuth, async (req, res) => {
    const { commentId } = req.params;
    
    try {
        // Check if comment belongs to user
        const comment = await db.query("SELECT user_id FROM comments WHERE id = $1", [commentId]);
        
        if (comment.rows.length > 0 && (comment.rows[0].user_id === req.user.id || req.user.role === 'admin')) {
            await db.query("DELETE FROM comments WHERE id = $1", [commentId]);
            return res.json({ success: true });
        }
        
        res.status(403).json({ success: false, message: "Unauthorized" });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});
// This crashes because 'req' doesn't exist here!
// 2. The route itself
// ... imports at the top ...

// 1. The route starts here
/* ---------------- FORUM ROUTES ---------------- */

// This is the "Container" that provides the 'req' and 'res' objects
// 1. THIS is the "building" (the route handler)
// This tells Express to wait for a "POST" request to /forum/create
/* ---------------- FORUM POST ROUTE ---------------- */

// This tells the server: "Wait for someone to submit the form"
// This is the "Container". Code inside here only runs when a user submits the form.
// Ensure the route matches the form action (/forum/create)
app.post("/forum/create", isAuth, upload.single('media'), async (req, res) => {
    try {
        const { content } = req.body; // Using 'content' from feed.ejs
        const authorId = req.user.id;
        
        // Ensure the path matches how you serve static files
        const mediaUrl = req.file ? `/uploads/${req.file.filename}` : null;

        if (!content) {
            return res.status(400).send("The scroll cannot be empty.");
        }

        await db.query(
            "INSERT INTO forum_posts (author_id, content, media_url, is_deleted) VALUES ($1, $2, $3, false)",
            [authorId, content, mediaUrl]
        );

        res.redirect("/feed");
    } catch (err) {
        console.error("POST ERROR:", err);
        // This is where your error message is coming from
        res.status(500).send("The Village Scroll could not be sealed: " + err.message);
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
    const targetUserId = req.params.id;
    const senderId = req.user.id;

    if (targetUserId == senderId) return res.redirect("/discover");

    try {
        // Check if request already exists
        const existing = await db.query(
            "SELECT * FROM friendships WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)",
            [senderId, targetUserId]
        );

        if (existing.rows.length === 0) {
            await db.query(
                "INSERT INTO friendships (user_id, friend_id, status) VALUES ($1, $2, 'pending')",
                [senderId, targetUserId]
            );
            
            // Optional: Create a notification for the receiver
            await db.query(
                "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, $2, $3)",
                [targetUserId, senderId, "Someone wants to start a kinship with you!"]
            );
        }

        res.redirect("/discover");
    } catch (err) {
        console.error(err);
        res.status(500).send("The messenger got lost.");
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
app.post("/friends/accept/:senderId", isAuth, async (req, res) => {
    const senderId = req.params.senderId;
    const userId = req.user.id;

    try {
        // Update friendship status
        await db.query(
            "UPDATE friendships SET status = 'accepted' WHERE user_id = $1 AND friend_id = $2",
            [senderId, userId]
        );

        // Mark notification as resolved so buttons disappear
        await db.query(
            "UPDATE notifications SET is_resolved = true WHERE user_id = $1 AND sender_id = $2 AND type = 'friend_request'",
            [userId, senderId]
        );

        res.redirect("/notifications");
    } catch (err) {
        res.status(500).send("Could not seal the kinship.");
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
    const userId = req.user.id;

    try {
        // 1. Fetch all posts by this specific user
        const userPosts = await db.query(`
            SELECT p.*, 
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
            (SELECT COUNT(*) FROM forum_replies WHERE post_id = p.id) AS comments_count
            FROM forum_posts p
            WHERE p.author_id = $1 AND p.is_deleted = false
            ORDER BY p.created_at DESC`, 
            [userId]
        );

        // 2. Fetch "Kinship" count (Friends/Followers)
        // Assuming you have a 'friends' or 'follows' table
        const kinship = await db.query(
            "SELECT COUNT(*) FROM users WHERE id != $1", // Placeholder: replace with actual follow logic
            [userId]
        );

        // 3. Render the page
        res.render("profile", {
            user: req.user,
            posts: userPosts.rows,
            friendCount: kinship.rows[0].count,
            unreadCount: res.locals.unreadCount || 0
        });

    } catch (err) {
        console.error("Profile Load Error:", err);
        res.status(500).send("The spirits are restless. Could not enter the hut.");
    }
});
app.get("/profile/:id", isAuth, async (req, res) => {
    const profileId = req.params.id;
    const loggedInUserId = req.user.id;

    try {
        // 1. Get the profile owner's info
        const userResult = await db.query("SELECT id, email, role, is_verified FROM users WHERE id = $1", [profileId]);
        
        if (userResult.rows.length === 0) {
            return res.status(404).send("This villager has vanished.");
        }

        const profileUser = userResult.rows[0];

        // 2. Get their posts (echoes)
        const postsResult = await db.query(`
            SELECT p.*, 
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
            (SELECT COUNT(*) FROM forum_replies WHERE post_id = p.id) AS comments_count
            FROM forum_posts p 
            WHERE p.author_id = $1 AND p.is_deleted = false
            ORDER BY p.created_at DESC`, 
            [profileId]
        );

        // 3. Get kinship (friend) count
        const friendsResult = await db.query(
            "SELECT COUNT(*) FROM friendships WHERE (user_id = $1 OR friend_id = $1) AND status = 'accepted'",
            [profileId]
        );

        res.render("profile", {
            user: profileUser, // The user whose profile we are viewing
            viewer: req.user,  // The person currently looking at the page
            posts: postsResult.rows,
            friendCount: friendsResult.rows[0].count
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("The village paths are blocked.");
    }
});

app.get("/notifications", isAuth, async (req, res) => {
    const userId = req.user.id;

    try {
        // 1. Fetch notifications with sender details
        const result = await db.query(`
            SELECT n.*, u.email AS sender_name, u.profile_pic AS sender_pic
            FROM notifications n
            LEFT JOIN users u ON n.sender_id = u.id
            WHERE n.user_id = $1
            ORDER BY n.created_at DESC
            LIMIT 50`, 
            [userId]
        );

        // 2. Mark all as read once the page is opened
        await db.query(
            "UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false",
            [userId]
        );

        res.render("notifications", {
            notifications: result.rows,
            user: req.user,
            unreadCount: 0 // Reset since we just marked them as read
        });
    } catch (err) {
        console.error("Alerts Error:", err);
        res.status(500).send("The village drums are silent. Error fetching alerts.");
    }
});

// ADD THIS: Clear Notifications Route
app.post("/notifications/clear", isAuth, async (req, res) => {
    try {
        await db.query("DELETE FROM notifications WHERE user_id = $1", [req.user.id]);
        res.redirect("/notifications");
    } catch (err) {
        res.status(500).send("The echoes refused to fade.");
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
// --- DO NOT PUT IT HERE (Global Scope) ---

app.get("/forum", async (req, res) => {
    try {
        const activeCat = req.query.cat || 'all';
        
        let query = `
            SELECT 
                forum_posts.*, 
                users.email AS author_email, 
                users.profile_pic AS author_pic 
            FROM forum_posts 
            LEFT JOIN users ON forum_posts.author_id = users.id
        `;
        
        let params = [];
        if (activeCat !== 'all') {
            query += ` WHERE category = $1`;
            params.push(activeCat);
        }
        
        query += ` ORDER BY created_at DESC`;

        const result = await db.query(query, params);

        // This makes sure the template has 'threads' and 'user'
        res.render("forum", { 
            threads: result.rows, 
            activeCat: activeCat,
            user: req.user || null 
        });
    } catch (err) {
        console.error("FORUM RENDER ERROR:", err);
        res.status(500).send(`The Great Hall is blocked: ${err.message}`);
    }
});
// index.js or routes/forum.js

/* ---------------- FORUM POST CREATION ---------------- */

// 1. ensureAuthenticated: stops crashes if req.user is missing
// 2. upload.single('media'): handles the image file
/* ---------------- FORUM POST CREATION ---------------- */

// 'media' here MUST match name="media" in your HTM1

// VIEW SINGLE THREAD
app.get("/forum/thread/:id", async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user ? req.user.id : 0;

        const threadResult = await db.query(`
            SELECT f.*, u.email AS author_email, u.profile_pic AS author_pic,
            (SELECT COUNT(*) FROM likes WHERE post_id = f.id) AS likes_count,
            (SELECT EXISTS (SELECT 1 FROM likes WHERE post_id = f.id AND user_id = $2)) AS liked_by_me
            FROM forum_posts f 
            JOIN users u ON f.author_id = u.id 
            WHERE f.id = $1`, [postId, userId]);

        const repliesResult = await db.query(`
            SELECT r.*, u.email AS author_email 
            FROM forum_replies r 
            JOIN users u ON r.author_id = u.id 
            WHERE r.post_id = $1 
            ORDER BY r.created_at ASC`, [postId]);

        res.render("thread", {
            thread: threadResult.rows[0],
            replies: repliesResult.rows,
            user: req.user
        });
    } catch (err) {
        res.status(500).send("Error reading scroll.");
    }
});

// <--- MAKE SURE NOTHING IS PASTED HERE!




// Helper for "Time Ago"
function formatTimeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return date.toLocaleDateString();
}
app.post("/forum/thread/:id/reply", async (req, res) => {
    try {
        const { reply_text } = req.body; // Matches <textarea name="reply_text">
        const postId = req.params.id;
        const userId = req.user.id;

        await db.query(`
            INSERT INTO forum_replies (reply_text, post_id, author_id) 
            VALUES ($1, $2, $3)
        `, [reply_text, postId, userId]);

        res.redirect(`/forum/thread/${postId}`);
    } catch (err) {
        console.error("REPLY ERROR:", err);
        res.status(500).send("The Great Hall rejected your reply.");
    }
});

// DELETE THREAD
app.post("/forum/thread/:id/delete", async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.id;

        // 1. Delete all likes associated with this post
        await db.query("DELETE FROM likes WHERE post_id = $1", [postId]);

        // 2. Delete all replies associated with this post
        await db.query("DELETE FROM forum_replies WHERE post_id = $1", [postId]);

        // 3. Finally, delete the post itself (only if the user owns it)
        const result = await db.query(
            "DELETE FROM forum_posts WHERE id = $1 AND author_id = $2", 
            [postId, userId]
        );

        if (result.rowCount === 0) {
            return res.status(403).send("You do not have permission to burn this scroll.");
        }

        res.redirect("/forum");
    } catch (err) {
        console.error("DELETE ERROR:", err);
        res.status(500).send("The Great Hall could not process this deletion.");
    }
});
app.post("/forum/post/:id/like", async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user?.id; // Check if user exists

        if (!userId) return res.status(401).json({ error: "Unauthorized" });

        // 1. Check if the like already exists
        const checkLike = await db.query(
            "SELECT * FROM likes WHERE post_id = $1 AND user_id = $2",
            [postId, userId]
        );

        if (checkLike.rows.length > 0) {
            // 2. If it exists, remove it (Unlike)
            await db.query("DELETE FROM likes WHERE post_id = $1 AND user_id = $2", [postId, userId]);
        } else {
            // 3. If not, add it (Like)
            await db.query("INSERT INTO likes (post_id, user_id) VALUES ($1, $2)", [postId, userId]);
        }

        // 4. Get the updated count to send back to the frontend
        const countResult = await db.query("SELECT COUNT(*) FROM likes WHERE post_id = $1", [postId]);
        
        res.json({ likesCount: countResult.rows[0].count });

    } catch (err) {
        console.error("LIKE ERROR:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

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
  // Inside your app.post("/like/:id")
  await db.query(
    "INSERT INTO notifications (user_id, sender_id, type, message) VALUES ($1, $2, $3, $4)",
    [postAuthorId, req.user.id, 'like', 'admired your echo']
);
console.log("Current user:", req.user.id);

});

app.get("/admin", isAdmin, async (req, res) => {
  const users = await db.query(
    "SELECT id, email, role, is_verified FROM users ORDER BY id DESC"
  );
  res.render("admin-dashboard", { users: users.rows });
});

/* ---------------- SERVER START ---------------- */
app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));
