import express from "express";
import passport from "../utils/passport.js";
import { registerUser, loginUser, logoutUser, googleAuthCallback } from "../controllers/authController.js";

const router = express.Router();

// Register & Login
router.get("/register", (req, res) => res.render("register"));
router.post("/register", registerUser);

router.get("/login", (req, res) => res.render("login"));
router.post("/login", passport.authenticate("local", {
  successRedirect: "/feed",
  failureRedirect: "/login",
  failureFlash: true,
}));

// Logout
router.get("/logout", logoutUser);

// Google OAuth
router.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/auth/google/callback", googleAuthCallback);

export default router;
