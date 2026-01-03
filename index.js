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
import { createServer } from 'http';
import { Server } from 'socket.io';
import { Resend } from "resend";
import 'dotenv/config';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import pkg from 'multer-storage-cloudinary';

const { PrismaClient } = pkg;
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const router = express.Router();
const PostgresStore = pgSession(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const httpServer = createServer(app);
const io = new Server(httpServer);

const onlineUsers = new Map(); // userId -> socketId
io.on('connection', (socket) => {
    // 1. Join Room
    socket.on('join', (userId) => {
        socket.join(`user_${userId}`); // Better than a Map for multi-tab support
        onlineUsers.set(String(userId), socket.id);
        console.log(`User ${userId} joined via socket ${socket.id}`);
    });

    // 2. Typing Indicator
    socket.on('typing', ({ receiverId, senderId, isTyping }) => {
        io.to(`user_${receiverId}`).emit('display_typing', { senderId, isTyping });
    });

    // 3. Private Message (MERGED)
    socket.on('private_message', async ({ senderId, receiverId, content }) => {
    try {
        // 1. Save the actual message to the messages table
        await db.query(
            "INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3)",
            [senderId, receiverId, content]
        );

        // 2. Create a notification record so it shows up in the Alerts page
        await db.query(
            `INSERT INTO notifications (user_id, sender_id, type, message, is_read, is_resolved) 
             VALUES ($1, $2, 'whisper', 'sent you a new whisper', false, true)`,
            [receiverId, senderId]
        );

        // 3. Send real-time data to the receiver if they are online
        io.to(`user_${receiverId}`).emit('new_whisper', {
            sender_id: senderId,
            content: content,
            created_at: new Date()
        });

        // 4. Trigger the notification alert (the red dot/popup)
        io.to(`user_${receiverId}`).emit('notification_received', {
            type: 'whisper',
            message: "New whisper received in your hut."
        });

    } catch (err) {
        console.error("Whisper Error:", err);
    }
});

    // 4. Friend Request (MOVED INSIDE)
    socket.on('send_request', async (data) => {
        const { senderId, receiverId } = data;
        io.to(`user_${receiverId}`).emit('notification_received', {
            type: 'friend_request',
            from: senderId,
            message: "A new soul seeks kinship."
        });
    });

    socket.on('disconnect', () => {
        // Cleanup onlineUsers Map
        for (let [userId, socketId] of onlineUsers.entries()) {
            if (socketId === socket.id) {
                onlineUsers.delete(userId);
                break;
            }
        }
    });
}); // <--- EVERYTHING SOCKET RELATED MUST BE ABOVE THIS BRACE
// 1. Initialize DB first
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
db.on("error", (err) => console.error("DB Error:", err));

// 2. Extract Cloudinary Constructor safely


// 3. Setup Storage (THE FIX IS HERE)
// 1. Switch to Memory Storage (Files will be in req.file.buffer)
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit for videos
    fileFilter: (req, file, cb) => {
        // Accept images and videos
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Only images and videos are allowed!'), false);
        }
    }
});

// Initialize Supabase Client (Make sure these are in your .env)
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);
/* 2. Second, define the specific folder path */
const uploadDir = path.join(__dirname, 'public/uploads');

/* 3. Now it is safe to check if it exists */
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}



db.on("error", (err) => console.error("Unexpected error on idle client", err));

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
  const userId = req.user.id;

  try {
    // 1. Fetch Trending Posts
    const trending = await db.query(`
      SELECT p.id, p.content, 
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as likes_count
      FROM forum_posts p 
      WHERE p.is_deleted = false 
      ORDER BY likes_count DESC LIMIT 5
    `);

    // 2. Fetch Suggested Villagers
    let villagerParams = [userId];
    let villagerQuery = `
      SELECT id, email, profile_pic FROM users 
      WHERE id != $1 
      AND id NOT IN (
          SELECT receiver_id FROM friendships WHERE sender_id = $1
          UNION
          SELECT sender_id FROM friendships WHERE receiver_id = $1
      )
    `;
    
    if (search) {
      villagerQuery += ` AND email ILIKE $2`;
      villagerParams.push(`%${search}%`);
    }
    
    const suggestedUsers = await db.query(villagerQuery + ` LIMIT 10`, villagerParams);

    // 3. Main Feed Query (Matched to EJS variable names)
    let params = [userId];
    let postsQuery = `
      SELECT p.*, 
             u.email AS author_email, 
             u.profile_pic AS author_pic, 
             u.is_verified,
             -- Change alias to match EJS: slikes_count
             (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS slikes_count,
             -- Change alias to match EJS: liked_by_me
             EXISTS (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = $1) AS liked_by_me,
             -- Aggregate comments
             (SELECT JSON_AGG(json_build_object(
                 'id', c.id,
                 'user_id', c.user_id,
                 'username', split_part(cu.email, '@', 1), 
                 'comment_text', c.reply_text 
             )) FROM comments c 
                JOIN users cu ON c.user_id = cu.id 
                WHERE c.post_id = p.id) as comments_list
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

    res.render("feed", {
      posts: posts.rows,
      trending: trending.rows,
      friends: suggestedUsers.rows,
      search: search,
      user: req.user,
      unreadCount: res.locals.unreadCount || 0
    });

  } catch (err) {
    console.error("FEED ERROR:", err);
    res.status(500).send("Village Square Error: Check Server Console");
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
// seeds.js snippet
const seedAncientScrolls = async () => {
    // 1. Create a Media Scroll (Testing your .post-image CSS)
    const mediaThread = await db.query(`
        INSERT INTO forum_threads (title, content, author_id, media_url, created_at)
        VALUES ('The Sunset over the Great Hall', 'A rare moment of peace.', 1, 'https://images.unsplash.com/photo-1464822759023-fed622ff2c3b', NOW())
        RETURNING id
    `);

    // 2. Create a Deep Chain (Testing your .reply-line CSS)
    const chainThread = await db.query(`
        INSERT INTO forum_threads (title, content, author_id, created_at)
        VALUES ('Proposed Village Law #4', 'Should we limit palm wine at festivals?', 2, NOW())
        RETURNING id
    `);
    const threadId = chainThread.rows[0].id;

    // 3. Loop to create 15 replies (Testing scrolling and vertical lines)
    for (let i = 1; i <= 15; i++) {
        await db.query(`
            INSERT INTO forum_replies (post_id, author_id, reply_text, created_at)
            VALUES ($1, $2, $3, NOW() + INTERVAL '${i} minutes')`,
            [threadId, (i % 2 === 0 ? 1 : 2), `Village Response #${i}: I believe the elders should decide.`]
        );
    }
};

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

// POST: Create a new Whisper (Forum Post)
// POST: Create a new post (Whisper)
app.post("/event/create", isAuth, upload.single('localMedia'), async (req, res) => {
    try {
        const { description } = req.body;
        const userId = req.user.id;
        
        let mediaUrl = null;
        let mediaType = 'text'; // Default to text if no file

        if (req.file) {
            const file = req.file;
            const fileExt = file.originalname.split('.').pop();
            const fileName = `${userId}-${Date.now()}.${fileExt}`;
            const filePath = `events/${fileName}`;

            // 1. Set mediaType for the frontend player
            mediaType = file.mimetype.startsWith('video') ? 'video' : 'image';

            // 2. Upload the buffer to your Supabase bucket
            const { data, error } = await supabase.storage
                .from('apugo_village')
                .upload(filePath, file.buffer, {
                    contentType: file.mimetype,
                    upsert: true
                });

            if (error) throw error;

            // 3. Generate the Public URL
            const { data: { publicUrl } } = supabase.storage
                .from('apugo_village')
                .getPublicUrl(filePath);
            
            mediaUrl = publicUrl;
        }

        // 4. Insert into PostgreSQL using your forum_posts table schema
        await db.query(
            "INSERT INTO forum_posts (content, image_url, media_type, author_id) VALUES ($1, $2, $3, $4)",
            [description, mediaUrl, mediaType, userId]
        );

        res.redirect("/feed");
    } catch (err) {
        console.error("SUPABASE UPLOAD ERROR:", err);
        res.status(500).send("The spirits are restless. We couldn't publish your event.");
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

app.post("/event/:id/like", checkVerified, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    // 1. Atomic Check & Toggle
    // We look for the like; if it exists, we delete it, otherwise we add it.
    const likeCheck = await db.query(
      "SELECT id FROM likes WHERE post_id = $1 AND user_id = $2",
      [postId, userId]
    );

    let isLiked = false;

    if (likeCheck.rows.length > 0) {
      // UNLIKE
      await db.query("DELETE FROM likes WHERE id = $1", [likeCheck.rows[0].id]);
      isLiked = false;
    } else {
      // LIKE
      await db.query("INSERT INTO likes (post_id, user_id) VALUES ($1, $2)", [
        postId,
        userId,
      ]);
      isLiked = true;
    }

    // 2. Get the updated count
    const countRes = await db.query(
      "SELECT COUNT(*) FROM likes WHERE post_id = $1",
      [postId]
    );
    
    // Ensure we send back a clean integer
    const likesCount = parseInt(countRes.rows[0].count);

    // 3. Send standardized JSON back
    // This matches the 'data.isLiked' and 'data.likesCount' your sendVibe() JS function uses
    res.json({
      success: true,
      isLiked: isLiked,
      likesCount: likesCount
    });

  } catch (err) {
    console.error("LIKE ERROR:", err);
    // Return success: false so the frontend can handle the error without breaking
    res.status(500).json({ success: false, message: "The vibe could not be sent." });
  }
});
app.post("/event/:postId/comment", isAuth, async (req, res) => {
    const { postId } = req.params;
    const { comment } = req.body; // The EJS sends { "comment": "..." }
    const userId = req.user.id;

    if (!comment || comment.trim() === "") {
        return res.status(400).json({ success: false, message: "Empty comment" });
    }

    try {
        // Insert into database using 'reply_text'
        const result = await db.query(
            `INSERT INTO comments (post_id, user_id, reply_text) 
             VALUES ($1, $2, $3) 
             RETURNING id`,
            [postId, userId, comment]
        );

        // Send back JSON so the EJS can update the page without refreshing
        res.json({
            success: true,
            commentId: result.rows[0].id,
            username: req.user.email.split('@')[0], // Extract username from email
            message: "Echo sent!"
        });

    } catch (err) {
        console.error("AJAX COMMENT ERROR:", err);
        res.status(500).json({ success: false, error: "Database error" });
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
// POST: Add an Echo (Reply)

app.post("/event/:id/bookmark", isAuth, async (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;

    try {
        // Check if already bookmarked
        const existing = await db.query(
            "SELECT id FROM bookmarks WHERE user_id = $1 AND post_id = $2",
            [userId, postId]
        );

        if (existing.rows.length > 0) {
            // Remove bookmark
            await db.query("DELETE FROM bookmarks WHERE id = $1", [existing.rows[0].id]);
            return res.json({ success: true, bookmarked: false });
        } else {
            // Add bookmark
            await db.query(
                "INSERT INTO bookmarks (user_id, post_id) VALUES ($1, $2)",
                [userId, postId]
            );
            return res.json({ success: true, bookmarked: true });
        }
    } catch (err) {
        console.error("BOOKMARK ERROR:", err);
        res.status(500).json({ success: false });
    }
});


app.post("/event/:id/delete", isAuth, async (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;

    try {
        // 1. Fetch the post to get the image URL and verify ownership
        const postResult = await db.query(
            "SELECT image_url, author_id FROM forum_posts WHERE id = $1", 
            [postId]
        );

        if (postResult.rows.length === 0) return res.status(404).send("Whisper not found.");
        const post = postResult.rows[0];

        // 2. Security: Only the author or an admin can delete
        if (post.author_id !== userId && req.user.role !== 'admin') {
            return res.status(403).send("You cannot silence someone else's whisper.");
        }

        // 3. If there's an image/video, delete it from Cloudinary
        if (post.image_url) {
            try {
                // Extracts 'folder/filename' from the URL
                const urlParts = post.image_url.split('/');
                const fileNameWithExtension = urlParts[urlParts.length - 1];
                const fileName = fileNameWithExtension.split('.')[0];
                const folderName = urlParts[urlParts.length - 2];
                const publicId = `${folderName}/${fileName}`;

                // Cloudinary destroy (supports image/video via resource_type: 'auto')
                await cloudinary.uploader.destroy(publicId);
            } catch (cloudErr) {
                console.error("Cloudinary Delete Error (Skipping):", cloudErr);
                // We continue even if Cloudinary fails so the DB stays clean
            }
        }

        // 4. Delete the post from DB (Foreign keys should handle comments/likes if set to CASCADE)
        await db.query("DELETE FROM forum_posts WHERE id = $1", [postId]);

        res.redirect("/feed");
    } catch (err) {
        console.error("DELETE ROUTE ERROR:", err);
        res.status(500).send("Failed to erase the whisper.");
    }
});

app.delete("/event/:postId/comment/:commentId", isAuth, async (req, res) => {
    const { commentId } = req.params;
    const userId = req.user.id;

    try {
        // Delete only if owner or admin
        const result = await db.query(
            "DELETE FROM comments WHERE id = $1 AND (user_id = $2 OR (SELECT role FROM users WHERE id = $2) = 'admin') RETURNING id",
            [commentId, userId]
        );

        if (result.rows.length > 0) {
            res.json({ success: true });
        } else {
            res.status(403).json({ success: false, message: "Unauthorized" });
        }
    } catch (err) {
        console.error(err);
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
        const { title, content, category, price } = req.body;
        const authorId = req.user.id;
        
        let mediaUrl = null;
        let mediaType = 'text';

        if (!title || !content) {
            return res.status(400).send("The decree must have a title and a message.");
        }

        const finalPrice = category === 'marketplace' && price ? parseFloat(price) : null;

        // --- Supabase Upload Logic ---
        if (req.file) {
            const file = req.file;
            const fileExt = file.originalname.split('.').pop();
            const fileName = `${authorId}-${Date.now()}.${fileExt}`;
            const filePath = `forum/${fileName}`;

            mediaType = file.mimetype.startsWith('video') ? 'video' : 'image';

            const { data, error } = await supabase.storage
                .from('apugo_village')
                .upload(filePath, file.buffer, {
                    contentType: file.mimetype,
                    upsert: true
                });

            if (error) throw error;

            const { data: { publicUrl } } = supabase.storage
                .from('apugo_village')
                .getPublicUrl(filePath);
            
            mediaUrl = publicUrl;
        }

        // --- Database Logic ---
        // Change 'forum_posts' to 'forum_threads' to match your GET route!
        const result = await db.query(
            `INSERT INTO forum_threads 
            (author_id, title, content, category, price, media_url, media_type, is_deleted) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, false) 
            RETURNING id`, 
            [authorId, title, content, category, finalPrice, mediaUrl, mediaType]
        );

        // Redirect directly to the newly created thread
        res.redirect(`/forum/thread/${result.rows[0].id}`);

    } catch (err) {
        console.error("POST ERROR:", err);
        res.status(500).send("The Village Scroll could not be sealed: " + err.message);
    }
});
/* ---------------- CHAT SYSTEM ---------------- */
app.get("/messages", isAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const friends = await db.query(
      `SELECT 
        u.id, 
        u.email, 
        u.profile_pic,
        (u.last_active > NOW() - INTERVAL '5 minutes') as is_online,
        f.status,
        -- Count unread messages specifically from this friend to the current user
        (SELECT COUNT(*) FROM messages m 
         WHERE m.sender_id = u.id 
         AND m.receiver_id = $1 
         AND m.is_read = false) as unread_count
      FROM users u
      JOIN friendships f ON (
        (f.sender_id = u.id AND f.receiver_id = $1) OR 
        (f.receiver_id = u.id AND f.sender_id = $1)
      )
      WHERE u.id != $1 
      AND f.status = 'accepted'
      ORDER BY is_online DESC, u.id DESC`,
      [userId]
    );

    res.render("messages", {
      friends: friends.rows,
      user: req.user,
    });
  } catch (err) {
    console.error("MESSAGES ROUTE ERROR:", err);
    res.redirect("/feed");
  }
});

// GET Chat History
app.get("/api/chat/:friendId", isAuth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, sender_id, receiver_id, content, created_at 
       FROM messages 
       WHERE (sender_id = $1 AND receiver_id = $2) 
          OR (sender_id = $2 AND receiver_id = $1) 
       ORDER BY created_at ASC`,
      [req.user.id, req.params.friendId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Ancient spirits blocked the history." });
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
app.post("/friends/request/:receiverId", isAuth, async (req, res) => {
    const senderId = req.user.id;
    const receiverId = req.params.receiverId;

    try {
        if (senderId == receiverId) return res.redirect("/villagers");

        const check = await db.query(
            "SELECT * FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
            [senderId, receiverId]
        );

        if (check.rows.length === 0) {
            // 1. Create the friendship record
            await db.query(
                "INSERT INTO friendships (sender_id, receiver_id, status) VALUES ($1, $2, 'pending')",
                [senderId, receiverId]
            );

            // 2. Create the notification record
            await db.query(
                `INSERT INTO notifications (user_id, sender_id, type, message, is_read) 
                 VALUES ($1, $2, 'friend_request', 'seeks kinship with you', false)`,
                [receiverId, senderId]
            );

            // 3. (Optional) Emit socket event for real-time pop-up
            // io.to(`user_${receiverId}`).emit('notification_received', {
            //    type: 'friend_request',
            //    message: 'Someone seeks kinship!'
            // });
        }
        
        res.redirect("/villagers"); 
    } catch (err) {
        console.error("FRIEND REQUEST ERROR:", err);
        res.status(500).send("Village Square Error");
    }
});

// 2. SEVER KINSHIP (UNFRIEND)
app.post("/friends/unfriend/:id", isAuth, async (req, res) => {
  try {
    await db.query(
      "DELETE FROM friendships WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)",
      [req.user.id, req.params.id]
    );
    // This is useful for the AJAX call in whispers
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
        return res.json({ success: true });
    }
    res.redirect("back");
  } catch (err) {
    res.status(500).send("Failed to sever bond.");
  }
});
app.post("/friends/accept/:senderId", isAuth, async (req, res) => {
    const senderId = req.params.senderId;
    const userId = req.user.id;

    try {
        // 1. Update status in friendships
        await db.query(
            "UPDATE friendships SET status = 'accepted' WHERE sender_id = $1 AND receiver_id = $2",
            [senderId, userId]
        );

        // 2. Mark the incoming notification as resolved
        await db.query(
            "UPDATE notifications SET is_resolved = true, is_read = true WHERE user_id = $1 AND sender_id = $2 AND type = 'friend_request'",
            [userId, senderId]
        );

        // 3. Notify the original sender that their request was accepted
        await db.query(
            `INSERT INTO notifications (user_id, sender_id, type, message, is_read) 
             VALUES ($1, $2, 'friend_accept', 'sealed a kinship with you', false)`,
            [senderId, userId]
        );

        // 4. (Optional) Real-time socket pulse to the sender
        // io.to(`user_${senderId}`).emit('notification_received', {
        //     type: 'friend_accept',
        //     message: 'Kinship sealed! You can now whisper.'
        // });

        res.redirect("/notifications");
    } catch (err) {
        console.error("ACCEPT ERROR:", err);
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
        const userPosts = await db.query(`
            SELECT p.*, 
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS slikes_count, -- Updated name
            (SELECT COUNT(*) FROM forum_replies WHERE post_id = p.id) AS comments_count,
            EXISTS (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = $1) AS liked_by_me -- Added check
            FROM forum_posts p
            WHERE p.author_id = $1 AND p.is_deleted = false
            ORDER BY p.created_at DESC`, 
            [userId]
        );

        // Fetch actual friendship count
        const kinship = await db.query(
            "SELECT COUNT(*) FROM friendships WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'accepted'",
            [userId]
        );

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
    const viewerId = req.user.id;

    try {
        const userResult = await db.query("SELECT id, email, role, is_verified, profile_pic FROM users WHERE id = $1", [profileId]);
        
        if (userResult.rows.length === 0) {
            return res.status(404).send("This villager has vanished.");
        }

        const profileUser = userResult.rows[0];

        // Fetch posts with viewer-specific like status
        const postsResult = await db.query(`
            SELECT p.*, 
            (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS slikes_count, -- Updated name
            (SELECT COUNT(*) FROM forum_replies WHERE post_id = p.id) AS comments_count,
            EXISTS (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = $2) AS liked_by_me -- Check if VIEWER liked it
            FROM forum_posts p 
            WHERE p.author_id = $1 AND p.is_deleted = false
            ORDER BY p.created_at DESC`, 
            [profileId, viewerId]
        );

        const friendsResult = await db.query(
            "SELECT COUNT(*) FROM friendships WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'accepted'",
            [profileId]
        );

        res.render("profile", {
            user: profileUser, 
            viewer: req.user,  
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
        // 1. Fetch notifications + sender info + CURRENT friendship status
        const result = await db.query(`
            SELECT 
                n.*, 
                u.email AS sender_name, 
                u.profile_pic AS sender_pic,
                f.status AS friendship_status -- Added to check if already 'accepted'
            FROM notifications n
            LEFT JOIN users u ON n.sender_id = u.id
            LEFT JOIN friendships f ON (
                (f.sender_id = n.sender_id AND f.receiver_id = n.user_id) OR
                (f.receiver_id = n.sender_id AND f.sender_id = n.user_id)
            )
            WHERE n.user_id = $1
            ORDER BY n.created_at DESC
            LIMIT 50`, 
            [userId]
        );

        // 2. Mark as read
        await db.query(
            "UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false",
            [userId]
        );

        res.render("notifications", {
            notifications: result.rows,
            user: req.user,
            unreadCount: 0 
        });
    } catch (err) {
        console.error("Alerts Error:", err);
        res.status(500).send("The village drums are silent.");
    }
});

// ADD THIS: Clear Notifications Route
app.post("/notifications/clear", isAuth, async (req, res) => {
    const userId = req.user.id;
    try {
        // 1. Wipe the echoes from the database
        await db.query("DELETE FROM notifications WHERE user_id = $1", [userId]);

        // 2. (Optional) If you have a real-time unread counter, reset it
        // io.to(`user_${userId}`).emit('clear_unread_count');

        res.redirect("/notifications");
    } catch (err) {
        console.error("CLEAR NOTIF ERROR:", err);
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
                f.*, 
                u.email AS author_email, 
                u.profile_pic AS author_pic,
                (SELECT COUNT(*) FROM forum_replies WHERE post_id = f.id) AS reply_count
            FROM forum_posts f
            LEFT JOIN users u ON f.author_id = u.id
            WHERE f.is_deleted = false
        `;
        
        let params = [];
        if (activeCat !== 'all') {
            query += ` AND f.category = $1`;
            params.push(activeCat);
        }
        
        query += ` ORDER BY f.created_at DESC`;

        const result = await db.query(query, params);

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

        // Standardized to forum_posts
        const threadResult = await db.query(`
            SELECT f.*, u.email AS author_email, u.profile_pic AS author_pic,
            (SELECT COUNT(*) FROM likes WHERE post_id = f.id) AS likes_count,
            (SELECT EXISTS (SELECT 1 FROM likes WHERE post_id = f.id AND user_id = $2)) AS liked_by_me
            FROM forum_posts f 
            JOIN users u ON f.author_id = u.id 
            WHERE f.id = $1 AND f.is_deleted = false`, [postId, userId]);

        if (threadResult.rows.length === 0) {
            return res.status(404).send("This scroll has been lost to time.");
        }

        const repliesResult = await db.query(`
            SELECT r.*, u.email AS author_email 
            FROM forum_replies r 
            JOIN users u ON r.author_id = u.id 
            WHERE r.post_id = $1 
            ORDER BY r.created_at ASC`, [postId]);

        res.render("thread", {
            thread: threadResult.rows[0],
            replies: repliesResult.rows,
            user: req.user || null
        });
    } catch (err) {
        console.error("GET THREAD ERROR:", err);
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
    // 1. Ensure user is logged in
    if (!req.isAuthenticated()) {
        return res.status(401).send("You must be a villager to speak here.");
    }

    const threadId = req.params.id;
    const { reply_text } = req.body;
    const authorId = req.user.id;

    // 2. Validation
    if (!reply_text || reply_text.trim().length === 0) {
        return res.status(400).send("A silent reply cannot be heard.");
    }

    try {
        // 3. Insert the reply
        // Make sure your table is 'forum_replies' and columns match!
        await db.query(
            `INSERT INTO forum_replies (post_id, author_id, reply_text, created_at) 
             VALUES ($1, $2, $3, NOW())`,
            [threadId, authorId, reply_text]
        );
        
        // 4. Return to the thread to see the message
        res.redirect(`/forum/thread/${threadId}`);
    } catch (err) {
        console.error("REPLY ERROR:", err);
        // This is what triggers your error message
        res.status(500).send("The village elders could not hear your reply: " + err.message);
    }
});
app.post("/forum/reply/:id/delete", async (req, res) => {
    const replyId = req.params.id;
    const { post_id } = req.body; // Passed via hidden input in your EJS

    try {
        // Ensure only the author can delete
        await db.query("DELETE FROM forum_replies WHERE id = $1 AND author_id = $2", [replyId, req.user.id]);
        res.redirect(`/forum/thread/${post_id}`);
    } catch (err) {
        res.status(500).send("Could not erase response.");
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
    if (!req.isAuthenticated()) return res.status(401).json({ error: "Login required" });

    const postId = req.params.id;
    const userId = req.user.id;

    try {
        // Check if already liked
        const checkLike = await db.query(
            "SELECT * FROM likes WHERE post_id = $1 AND user_id = $2",
            [postId, userId]
        );

        if (checkLike.rows.length > 0) {
            // Unlike
            await db.query("DELETE FROM likes WHERE post_id = $1 AND user_id = $2", [postId, userId]);
        } else {
            // Like
            await db.query("INSERT INTO likes (post_id, user_id) VALUES ($1, $2)", [postId, userId]);
        }

        // Get updated count
        const countRes = await db.query("SELECT COUNT(*) FROM likes WHERE post_id = $1", [postId]);
        
        res.json({ 
            likesCount: countRes.rows[0].count,
            isLiked: checkLike.rows.length === 0 
        });
    } catch (err) {
        console.error("LIKE ERROR:", err);
        res.status(500).json({ error: "Database error" });
    }
});

app.get("/villagers", isAuth, async (req, res) => {
    const userId = req.user.id;
    const search = req.query.search || "";

    try {
        const query = `
            SELECT u.id, u.email, u.is_verified, u.profile_pic,
            (SELECT status FROM friendships 
             WHERE (sender_id = $1 AND receiver_id = u.id) 
             OR (sender_id = u.id AND receiver_id = $1) 
             LIMIT 1) as friend_status
            FROM users u
            WHERE u.id != $1
            AND (u.email ILIKE $2)
            ORDER BY u.id DESC
        `;
        
        const result = await db.query(query, [userId, `%${search}%`]);

        res.render("villagers", {
            villagers: result.rows,
            search: search,
            user: req.user
        });
    } catch (err) {
        console.error("VILLAGERS ROUTE ERROR:", err);
        res.status(500).send("The Village Directory is currently unavailable.");
    }
});


app.get("/admin", isAdmin, async (req, res) => {
  const users = await db.query(
    "SELECT id, email, role, is_verified FROM users ORDER BY id DESC"
  );
  res.render("admin-dashboard", { users: users.rows });
});

/* ---------------- SERVER START ---------------- */
// WRONG: app.listen(3000); 

// RIGHT:
httpServer.listen(3000, () => {
    console.log('Server and Sockets active on port 3000');
});

