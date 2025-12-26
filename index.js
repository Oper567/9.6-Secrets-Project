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
import { Resend } from "resend";

dotenv.config();

/* ---------------- BASIC SETUP ---------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

/* ---------------- DATABASE ---------------- */
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

db.on("error", err => console.error("PG ERROR:", err));

/* ---------------- SUPABASE ---------------- */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

/* ---------------- MAIL (RESEND) ---------------- */
const resend = new Resend(process.env.RESEND_API_KEY);

/* ---------------- FILE UPLOAD ---------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* ---------------- SESSION ---------------- */
const PostgresStore = pgSession(session);
app.use(
  session({
    store: new PostgresStore({
      pool: db,
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
    }
  })
);

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

/* ---------------- GLOBAL LOCALS ---------------- */
app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.messages = req.flash();
  res.locals.unreadCount = 0;

  if (req.isAuthenticated()) {
    try {
      await db.query(
        "UPDATE users SET last_active = NOW() WHERE id = $1",
        [req.user.id]
      );

      const notes = await db.query(
        "SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND is_read=false",
        [req.user.id]
      );
      res.locals.unreadCount = notes.rows[0].count;
    } catch (err) {
      console.error("LOCALS ERROR:", err);
    }
  }
  next();
});

/* ---------------- AUTH HELPERS ---------------- */
const isAuth = (req, res, next) =>
  req.isAuthenticated() ? next() : res.redirect("/login");

const checkVerified = (req, res, next) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (!req.user.is_verified)
    return res.render("verify-email-notice", { email: req.user.email });
  next();
};

const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === "admin") return next();
  req.flash("error", "Admins only");
  res.redirect("/feed");
};

/* ---------------- PASSPORT ---------------- */
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE email=$1",
        [email.toLowerCase()]
      );
      if (!result.rows.length) return done(null, false);

      const user = result.rows[0];
      if (user.password === "google-oauth")
        return done(null, false, { message: "Use Google login" });

      const valid = await bcrypt.compare(password, user.password);
      return valid ? done(null, user) : done(null, false);
    } catch (err) {
      done(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      proxy: true
    },
    async (_, __, profile, done) => {
      try {
        const email = profile.emails[0].value.toLowerCase();
        const existing = await db.query(
          "SELECT * FROM users WHERE email=$1",
          [email]
        );
        if (existing.rows.length) return done(null, existing.rows[0]);

        const created = await db.query(
          "INSERT INTO users (email,password,role,is_verified) VALUES ($1,$2,$3,true) RETURNING *",
          [email, "google-oauth", "user"]
        );
        done(null, created.rows[0]);
      } catch (err) {
        done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, res.rows[0]);
  } catch (err) {
    done(err);
  }
});

/* ---------------- AUTH ROUTES ---------------- */
app.get("/", (_, res) => res.render("home"));
app.get("/login", (_, res) => res.render("login"));
app.get("/register", (_, res) => res.render("register"));

app.post("/register", async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, saltRounds);
    await db.query(
      "INSERT INTO users (email,password,role,is_verified) VALUES ($1,$2,'user',true)",
      [req.body.email.toLowerCase(), hash]
    );
    req.flash("success", "Account created");
    res.redirect("/login");
  } catch {
    req.flash("error", "Email exists");
    res.redirect("/register");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/feed",
    failureRedirect: "/login",
    failureFlash: true
  })
);

app.get("/logout", (req, res) =>
  req.logout(() => res.redirect("/"))
);

/* ---------------- FEED ---------------- */
app.get("/feed", checkVerified, async (req, res) => {
  try {
    const posts = await db.query(`
      SELECT e.*, u.email AS author,
      (SELECT COUNT(*) FROM likes WHERE event_id=e.id) AS likes_count
      FROM events e
      JOIN users u ON u.id=e.created_by
      WHERE e.is_deleted=false
      ORDER BY e.created_at DESC
    `);

    res.render("feed", { posts: posts.rows });
  } catch (err) {
    res.status(500).send("Feed error");
  }
});

/* ---------------- LIKE (FIXED) ---------------- */
app.post("/event/:id/like", checkVerified, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const existing = await db.query(
      "SELECT * FROM likes WHERE event_id=$1 AND user_id=$2",
      [id, userId]
    );

    if (existing.rows.length) {
      await db.query("DELETE FROM likes WHERE id=$1", [
        existing.rows[0].id
      ]);
    } else {
      await db.query(
        "INSERT INTO likes (event_id,user_id) VALUES ($1,$2)",
        [id, userId]
      );
    }

    const count = await db.query(
      "SELECT COUNT(*) FROM likes WHERE event_id=$1",
      [id]
    );

    res.json({ success: true, count: count.rows[0].count });
  } catch {
    res.status(500).json({ success: false });
  }
});

/* ---------------- CHAT (DEDUPED) ---------------- */
app.get("/messages", isAuth, async (req, res) => {
  const friends = await db.query(`
    SELECT u.id,u.email FROM users u
    JOIN friendships f ON (f.sender_id=u.id OR f.receiver_id=u.id)
    WHERE (f.sender_id=$1 OR f.receiver_id=$1)
    AND u.id != $1 AND f.status='accepted'
  `,[req.user.id]);

  res.render("messages", { friends: friends.rows });
});

app.get("/api/chat/:friendId", isAuth, async (req, res) => {
  const rows = await db.query(`
    SELECT * FROM messages
    WHERE (sender_id=$1 AND receiver_id=$2)
    OR (sender_id=$2 AND receiver_id=$1)
    ORDER BY created_at ASC
  `,[req.user.id, req.params.friendId]);

  res.json(rows.rows);
});

app.delete("/api/chat/clear/:friendId", isAuth, async (req, res) => {
  await db.query(
    "DELETE FROM messages WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1)",
    [req.user.id, req.params.friendId]
  );
  res.json({ success: true });
});

/* ---------------- ADMIN ---------------- */
app.get("/admin", isAdmin, async (_, res) => {
  const users = await db.query(
    "SELECT id,email,role,is_verified FROM users"
  );
  res.render("admin-dashboard", { users: users.rows });
});

/* ---------------- SERVER ---------------- */
app.listen(port, () =>
  console.log(`🚀 Apugo running on port ${port}`)
);
