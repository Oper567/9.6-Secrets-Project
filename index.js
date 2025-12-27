import express from "express";
import bodyParser from "body-parser";
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
import pkg from "@prisma/client";

dotenv.config();
const { PrismaClient } = pkg;
const prisma = new PrismaClient();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

const PostgresStore = pgSession(session);

// Supabase & Resend
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const resend = new Resend(process.env.EMAIL_PASS);

// Multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ---------------- MIDDLEWARE ----------------
app.set("trust proxy", 1);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(session({
  store: new PostgresStore({
    pool: prisma.$connect, // Use prisma connection pool here
    tableName: "session",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "apugo_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  }
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.messages = req.flash();
  res.locals.unreadCount = 0;

  if (req.isAuthenticated()) {
    try {
      await prisma.user.update({
        where: { id: req.user.id },
        data: { lastActive: new Date() }
      });
      const noteCount = await prisma.notification.count({
        where: { userId: req.user.id, isRead: false }
      });
      res.locals.unreadCount = noteCount;
    } catch (e) { console.error(e); }
  }
  next();
});

// ---------------- AUTH HELPERS ----------------
function isAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

function checkVerified(req, res, next) {
  if (req.isAuthenticated() && req.user.isVerified) return next();
  if (req.isAuthenticated()) return res.render("verify-email-notice", { email: req.user.email });
  res.redirect("/login");
}

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === "admin") return next();
  req.flash("error", "Access denied. Elders only!");
  res.redirect("/feed");
}

// ---------------- PASSPORT ----------------
passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user) return done(null, false, { message: "User not found" });
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
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          email,
          password: "google-oauth",
          role: "user",
          isVerified: true
        }
      });
    }
    return done(null, user);
  } catch (err) { return done(err); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) { done(err); }
});

// ---------------- AUTH ROUTES ----------------
app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    await prisma.user.create({
      data: { email: email.toLowerCase(), password: hash, role: "user", isVerified: true }
    });
    req.flash("success", "Registration successful! Welcome to the village.");
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    req.flash("error", "Email already exists.");
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
  req.logout(err => res.redirect("/"));
});

// ---------------- FORGOT/RESET PASSWORD ----------------
app.get("/forgot-password", (req, res) => res.render("forgot-password", { message: null, error: null }));

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user) return res.render("forgot-password", { message: null, error: "Email not found." });

    const token = Math.random().toString(36).substring(2, 15);
    await prisma.user.update({
      where: { email },
      data: { resetToken: token, resetExpires: new Date(Date.now() + 3600000) }
    });

    const resetLink = `${req.protocol}://${req.get("host")}/reset-password/${token}`;
    await resend.emails.send({
      from: "Apugo <onboarding@resend.dev>",
      to: [email],
      subject: "Apugo Village | Password Reset",
      html: `<p>Reset your password: <a href="${resetLink}">${resetLink}</a></p>`
    });

    res.render("forgot-password", { message: "Reset link sent!", error: null });
  } catch (err) {
    console.error(err);
    res.render("forgot-password", { message: null, error: "Could not send reset link." });
  }
});

app.get("/reset-password/:token", (req, res) => res.render("reset-password", { token: req.params.token }));
app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    const user = await prisma.user.updateMany({
      where: { resetToken: token, resetExpires: { gte: new Date() } },
      data: { password: hash, resetToken: null, resetExpires: null }
    });
    if (user.count > 0) req.flash("success", "Password updated!");
    res.redirect("/login");
  } catch (err) { res.redirect("/login"); }
});

// ---------------- FEED ----------------
app.get("/feed", checkVerified, async (req, res) => {
  const search = req.query.search || "";
  try {
    const posts = await prisma.event.findMany({
      where: { 
        isAnnouncement: false,
        isDeleted: false,
        OR: [
          { description: { contains: search } },
          { author: { email: { contains: search } } }
        ]
      },
      include: { author: true, comments: { include: { user: true } }, likes: true },
      orderBy: [{ isPinned: "desc" }, { createdAt: "desc" }]
    });

    const trending = await prisma.event.findMany({
      where: { isDeleted: false },
      include: { likes: true },
      orderBy: { likes: { _count: "desc" } },
      take: 3
    });

    const suggestedUsers = await prisma.user.findMany({
      where: { id: { not: req.user.id } },
      take: 10
    });

    const announcements = await prisma.event.findMany({
      where: { isAnnouncement: true, isDeleted: false },
      include: { author: true },
      orderBy: { createdAt: "desc" }
    });

    res.render("feed", { posts, trending, suggestedUsers, announcements, search, user: req.user });
  } catch (err) { console.error(err); res.status(500).send("Feed Error"); }
});

// ---------------- CHAT ----------------
app.get("/chat", checkVerified, async (req, res) => {
  try {
    const messages = await prisma.chat.findMany({
      include: { user: true },
      orderBy: { createdAt: "asc" }
    });
    res.render("chat", { messages });
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not load chat.");
  }
});

app.post("/chat", checkVerified, async (req, res) => {
  try {
    const { message } = req.body;
    await prisma.chat.create({
      data: {
        message,
        userId: req.user.id
      }
    });
    res.redirect("/chat");
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not send message.");
  }
});

// ---------------- FORUM ----------------
app.get("/forum", checkVerified, async (req, res) => {
  try {
    const threads = await prisma.forumThread.findMany({
      include: { author: true, posts: { include: { author: true } } },
      orderBy: { createdAt: "desc" }
    });
    res.render("forum", { threads });
  } catch (err) {
    console.error(err);
    res.status(500).send("Forum error");
  }
});

app.post("/forum/new-thread", checkVerified, async (req, res) => {
  try {
    const { title, content } = req.body;
    await prisma.forumThread.create({
      data: {
        title,
        authorId: req.user.id,
        posts: { create: { content, authorId: req.user.id } }
      }
    });
    res.redirect("/forum");
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not create thread.");
  }
});

app.post("/forum/post", checkVerified, async (req, res) => {
  try {
    const { threadId, content } = req.body;
    await prisma.forumPost.create({
      data: { threadId: parseInt(threadId), content, authorId: req.user.id }
    });
    res.redirect("/forum");
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not post reply.");
  }
});

// ---------------- EVENTS ----------------
app.get("/events", checkVerified, async (req, res) => {
  try {
    const events = await prisma.event.findMany({
      where: { isDeleted: false },
      include: { author: true },
      orderBy: { createdAt: "desc" }
    });
    res.render("events", { events });
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not load events.");
  }
});

app.post("/events/new", checkVerified, upload.single("image"), async (req, res) => {
  try {
    const { title, description } = req.body;
    const imageUrl = req.file
      ? (await supabase.storage.from("event-images").upload(`images/${Date.now()}-${req.file.originalname}`, req.file.buffer)).data.path
      : null;

    await prisma.event.create({
      data: {
        title,
        description,
        imageUrl,
        authorId: req.user.id
      }
    });
    res.redirect("/events");
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not create event.");
  }
});

// ---------------- LIKES ----------------
app.post("/like", checkVerified, async (req, res) => {
  try {
    const { eventId } = req.body;
    const existing = await prisma.like.findUnique({
      where: { userId_eventId: { userId: req.user.id, eventId: parseInt(eventId) } }
    });

    if (existing) {
      await prisma.like.delete({ where: { userId_eventId: { userId: req.user.id, eventId: parseInt(eventId) } } });
    } else {
      await prisma.like.create({
        data: { userId: req.user.id, eventId: parseInt(eventId) }
      });
    }

    res.redirect("/feed");
  } catch (err) {
    console.error(err);
    res.status(500).send("Like action failed.");
  }
});

// ---------------- VILLAGER SEARCH ----------------
app.get("/villagers", checkVerified, async (req, res) => {
  const search = req.query.search || "";
  try {
    const villagers = await prisma.user.findMany({
      where: {
        email: { contains: search },
        id: { not: req.user.id }
      },
      take: 20
    });
    res.render("villagers", { villagers, search });
  } catch (err) {
    console.error(err);
    res.status(500).send("Villager search failed.");
  }
});

// ---------------- ADMIN ----------------
app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    const posts = await prisma.event.findMany({ include: { author: true } });
    res.render("admin", { users, posts });
  } catch (err) {
    console.error(err);
    res.status(500).send("Admin panel error");
  }
});

app.post("/admin/delete-user", isAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    await prisma.user.delete({ where: { id: parseInt(userId) } });
    res.redirect("/admin");
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not delete user.");
  }
});

app.post("/admin/delete-post", isAdmin, async (req, res) => {
  try {
    const { postId } = req.body;
    await prisma.event.update({ where: { id: parseInt(postId) }, data: { isDeleted: true } });
    res.redirect("/admin");
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not delete post.");
  }
});


// ---------------- SERVER START ----------------
app.listen(port, () => console.log(`🚀 Village Square live at port ${port}`));
