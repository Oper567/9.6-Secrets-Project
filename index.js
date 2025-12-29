import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import pgSession from "connect-pg-simple";
import passport from "passport";
import flash from "connect-flash";
import path from "path";
import { fileURLToPath } from "url";
import 'dotenv/config';

import { db } from "./utils/db.js";
import { passportConfig } from "./utils/passport.js";
import { errorHandler } from "./middleware/errorMiddleware.js";

// Routes
import authRoutes from "./routes/authRoutes.js";
import feedRoutes from "./routes/feedRoutes.js";
import chatRoutes from "./routes/chatRoutes.js";
import postRoutes from "./routes/postRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import notificationRoutes from "./routes/notificationRoutes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PostgresStore = pgSession(session);
const port = process.env.PORT || 3000;

// ---------------- MIDDLEWARE ----------------
app.set("trust proxy", 1);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

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
passportConfig(passport); // initialize passport strategies
app.use(passport.initialize());
app.use(passport.session());

// Global locals
app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.messages = req.flash();
  res.locals.unreadCount = 0;
  res.locals.search = "";
  next();
});

// ---------------- ROUTES ----------------
app.use("/", authRoutes);
app.use("/feed", feedRoutes);
app.use("/chat", chatRoutes);
app.use("/post", postRoutes);
app.use("/user", userRoutes);
app.use("/notifications", notificationRoutes);

// ---------------- ERROR HANDLER ----------------
app.use(errorHandler);

// ---------------- SERVER ----------------
app.listen(port, () => console.log(`Server running on port ${port}`));
