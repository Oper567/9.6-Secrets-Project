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

dotenv.config();

/* ================== BASIC SETUP ================== */

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ================== DATABASE ================== */

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

db.on("error", err => console.error("DB Error:", err));

/* ================== SESSION STORE ================== */

const PostgresStore = pgSession(session);

/* ================== SUPABASE ================== */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

/* ================== MAILER ================== */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/* ================== MULTER ================== */

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
});

/* ================== APP MIDDLEWARE ================== */

app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    store: new PostgresStore({
      pool: db,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

/* ================== GLOBAL LOCALS ================== */

app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.messages = req.flash();
  res.locals.unreadCount = 0;

  if (req.isAuthenticated()) {
    await db.query(
      "UPDATE users SET last_active = NOW() WHERE id = $1",
      [req.user.id]
    );

    const unread = await db.query(
      "SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND is_read=false",
      [req.user.id]
    );
    res.locals.unreadCount = unread.rows[0].count;
  }

  next();
});

/* ================== HELPERS ================== */

const isAuth = (req, res, next) =>
  req.isAuthenticated() ? next() : res.redirect("/login");

const isVerified = (req, res, next) =>
  req.user.is_verified ? next() : res.redirect("/profile");

const isAdmin = (req, res, next) =>
  req.user.role === "admin" ? next() : res.redirect("/feed");

const sendWelcomeNote = async userId => {
  await db.query(
    "INSERT INTO notifications (user_id, sender_id, message) VALUES ($1, 1, $2)",
    [userId, "Welcome to Apugo Village 🌴"]
  );
};

/* ================== PASSPORT ================== */

passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const result = await db.query(
          "SELECT * FROM users WHERE email=$1",
          [email.toLowerCase()]
        );
        if (!result.rows.length) return done(null, false);

        const user = result.rows[0];
        if (!user.is_verified) return done(null, false);

        const valid = await bcrypt.compare(password, user.password);
        return valid ? done(null, user) : done(null, false);
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
    async (_, __, profile, done) => {
      const email = profile.emails[0].value.toLowerCase();
      const user = await db.query(
        "SELECT * FROM users WHERE email=$1",
        [email]
      );

      if (user.rows.length) return done(null, user.rows[0]);

      const created = await db.query(
        "INSERT INTO users (email,password,role,is_verified) VALUES ($1,$2,'user',true) RETURNING *",
        [email, "google-oauth"]
      );

      await sendWelcomeNote(created.rows[0].id);
      done(null, created.rows[0]);
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await db.query("SELECT * FROM users WHERE id=$1", [id]);
  done(null, user.rows[0]);
});

/* ================== AUTH ROUTES ================== */

app.get("/", (_, res) => res.render("home"));
app.get("/login", (_, res) => res.render("login"));
app.get("/register", (_, res) => res.render("register"));

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, saltRounds);
  const token = crypto.randomUUID();

  const user = await db.query(
    "INSERT INTO users (email,password,role,is_verified,verification_token) VALUES ($1,$2,'user',false,$3) RETURNING *",
    [email.toLowerCase(), hash, token]
  );

  const link = `https://${req.get("host")}/verify/${token}`;

  await transporter.sendMail({
    to: email,
    subject: "Verify Apugo Account",
    html: `<a href="${link}">Verify Account</a>`,
  });

  await sendWelcomeNote(user.rows[0].id);
  res.render("verify-email-notice", { email });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/feed",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

app.get("/verify/:token", async (req, res) => {
  await db.query(
    "UPDATE users SET is_verified=true, verification_token=NULL WHERE verification_token=$1",
    [req.params.token]
  );
  res.redirect("/login");
});

/* ================== FEED ================== */

app.get("/feed", isAuth, isVerified, async (req, res) => {
  const posts = await db.query(
    "SELECT e.*, u.email FROM events e JOIN users u ON e.created_by=u.id WHERE is_deleted=false ORDER BY created_at DESC"
  );
  res.render("feed", { posts: posts.rows });
});

/* ================== EVENTS ================== */

app.post(
  "/event/create",
  isAuth,
  isVerified,
  upload.single("media"),
  async (req, res) => {
    let mediaUrl = null;

    if (req.file) {
      const name = `${Date.now()}-${req.file.originalname}`;
      await supabase.storage
        .from("apugo_village")
        .upload(name, req.file.buffer);

      mediaUrl = supabase.storage
        .from("apugo_village")
        .getPublicUrl(name).data.publicUrl;
    }

    await db.query(
      "INSERT INTO events (description,image_url,created_by) VALUES ($1,$2,$3)",
      [req.body.description, mediaUrl, req.user.id]
    );

    res.redirect("/feed");
  }
);

/* ================== PROFILE ================== */

app.get("/profile", isAuth, async (req, res) => {
  const posts = await db.query(
    "SELECT * FROM events WHERE created_by=$1 AND is_deleted=false",
    [req.user.id]
  );
  res.render("profile", { posts: posts.rows });
});

/* ================== ADMIN ================== */

app.get("/admin", isAuth, isAdmin, async (req, res) => {
  const users = await db.query(
    "SELECT id,email,role,is_verified FROM users"
  );
  res.render("admin-dashboard", { users: users.rows });
});

/* ================== START ================== */

app.listen(port, () =>
  console.log(`🚀 Apugo running on port ${port}`)
);
