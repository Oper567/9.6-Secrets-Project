import express from "express";
import bodyParser from "body-parser";
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
import { createClient } from "@supabase/supabase-js";
import { Resend } from "resend";

dotenv.config();

/* ---------------- BASIC SETUP ---------------- */
const app = express();
const port = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ---------------- SUPABASE ---------------- */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
// 2️⃣ Subscribe to a realtime channel
const channel = supabase
  .channel("chat-room") // ⚠️ This is JS, not SQL
  .on(
    "postgres_changes",
    { event: "INSERT", schema: "public", table: "messages" },
    (payload) => {
      console.log("New message:", payload.new);
    }
  )
  .subscribe();

/* ---------------- MAIL ---------------- */
const resend = new Resend(process.env.RESEND_API_KEY);

/* ---------------- MULTER ---------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
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

  if (req.user) {
    const { count } = await supabase
      .from("notifications")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.user.id)
      .eq("is_read", false);

    res.locals.unreadCount = count || 0;
  }
  next();
});

/* ---------------- AUTH HELPERS ---------------- */
const isAuth = (req, res, next) =>
  req.isAuthenticated() ? next() : res.redirect("/login");

const checkVerified = (req, res, next) =>
  req.user?.is_verified ? next() : res.redirect("/login");

const isAdmin = (req, res, next) =>
  req.user?.role === "admin" ? next() : res.redirect("/feed");

/* ---------------- PASSPORT ---------------- */
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      const { data: user } = await supabase
        .from("users")
        .select("*")
        .eq("email", email.toLowerCase())
        .single();

      if (!user) return done(null, false);

      const ok = await bcrypt.compare(password, user.password);
      return ok ? done(null, user) : done(null, false);
    }
  )
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (_, __, profile, done) => {
      const email = profile.emails[0].value.toLowerCase();

      let { data: user } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();

      if (!user) {
        const { data } = await supabase.from("users").insert({
          email,
          password: "google-oauth",
          is_verified: true,
          role: "user",
        }).select().single();
        user = data;
      }

      done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const { data } = await supabase.from("users").select("*").eq("id", id).single();
  done(null, data);
});

/* ---------------- AUTH ROUTES ---------------- */
app.get("/", (_, res) => res.render("home"));
app.get("/login", (_, res) => res.render("login"));
app.get("/register", (_, res) => res.render("register"));

app.post("/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);

  await supabase.from("users").insert({
    email: req.body.email.toLowerCase(),
    password: hash,
    is_verified: true,
    role: "user",
  });

  res.redirect("/login");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/feed",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/logout", (req, res) =>
  req.logout(() => res.redirect("/"))
);

/* ---------------- FEED ---------------- */
app.get("/feed", checkVerified, async (req, res) => {
  const { data: posts } = await supabase
    .from("events")
    .select(`
      *,
      users(email, profile_pic),
      likes(count),
      comments(*)
    `)
    .eq("is_deleted", false)
    .order("created_at", { ascending: false });

  res.render("feed", { posts });
});

/* ---------------- CREATE POST ---------------- */
app.post(
  "/event/create",
  checkVerified,
  upload.single("localMedia"),
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

    await supabase.from("events").insert({
      description: req.body.description,
      image_url: mediaUrl,
      created_by: req.user.id,
      is_announcement: req.user.role === "admin",
    });

    res.redirect("/feed");
  }
);

/* ---------------- LIKE ---------------- */
app.post("/event/:id/like", isAuth, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  const { data: existing } = await supabase
    .from("likes")
    .select("*")
    .eq("event_id", postId)
    .eq("user_id", userId)
    .single();

  if (existing) {
    await supabase.from("likes").delete().eq("id", existing.id);
  } else {
    await supabase.from("likes").insert({ event_id: postId, user_id: userId });
  }

  const { count } = await supabase
    .from("likes")
    .select("*", { count: "exact", head: true })
    .eq("event_id", postId);

  res.json({ success: true, newCount: count });
});

/* ---------------- COMMENT ---------------- */
app.post("/event/:id/comment", isAuth, async (req, res) => {
  await supabase.from("comments").insert({
    event_id: req.params.id,
    user_id: req.user.id,
    content: req.body.comment,
  });
  res.redirect("/feed");
});

/* ---------------- CHAT ---------------- */
app.get("/api/chat/:friendId", isAuth, async (req, res) => {
  const { data } = await supabase
    .from("messages")
    .select("*")
    .or(
      `and(sender_id.eq.${req.user.id},receiver_id.eq.${req.params.friendId}),
       and(sender_id.eq.${req.params.friendId},receiver_id.eq.${req.user.id})`
    )
    .order("created_at");

  res.json(data);
});

app.post("/api/chat/send", isAuth, async (req, res) => {
  const { data } = await supabase.from("messages").insert({
    sender_id: req.user.id,
    receiver_id: req.body.receiverId,
    content: req.body.content,
  }).select().single();

  res.json(data);
});
// View forum
app.get("/", async (req, res) => {
  const { data } = await supabase
    .from("forum_threads")
    .select("*, users(email, profile_pic)")
    .order("created_at", { ascending: false });

  res.render("forum", { threads: data, user: req.user });
});

// Create thread
app.post("/create", async (req, res) => {
  await supabase.from("forum_threads").insert({
    title: req.body.title,
    content: req.body.content,
    category: req.body.category,
    author_id: req.user.id,
  });

  res.redirect("/forum");
});

// View single thread
app.get("/thread/:id", async (req, res) => {
  await supabase
    .from("forum_threads")
    .update({ view_count: supabase.sql`view_count + 1` })
    .eq("id", req.params.id);

  const { data: thread } = await supabase
    .from("forum_threads")
    .select("*, users(email, profile_pic)")
    .eq("id", req.params.id)
    .single();

  const { data: replies } = await supabase
    .from("forum_replies")
    .select("*, users(email, profile_pic)")
    .eq("thread_id", req.params.id);

  res.render("thread", { thread, replies, user: req.user });
});

export default router;

/* ---------------- SERVER ---------------- */
app.listen(port, () =>
  console.log(`🚀 Apugo Village running on port ${port}`)
);
