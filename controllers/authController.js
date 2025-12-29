import bcrypt from "bcryptjs";
import { db } from "../utils/db.js";
import passport from "../utils/passport.js";
import { sendWelcomeNote, sendVerificationEmail } from "../utils/email.js";

export const registerUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    const existing = await db.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (existing.rows.length) {
      req.flash("error", "Email already exists");
      return res.redirect("/register");
    }

    const result = await db.query(
      "INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING *",
      [email.toLowerCase(), hashed, "user", false]
    );

    await sendVerificationEmail(result.rows[0].id, email);
    req.flash("success", "Account created! Check your email to verify.");
    res.redirect("/login");
  } catch (err) {
    next(err);
  }
};

export const logoutUser = (req, res) => {
  req.logout(err => {
    if (err) console.log(err);
    res.redirect("/login");
  });
};

export const googleAuthCallback = passport.authenticate("google", {
  failureRedirect: "/login",
  successRedirect: "/feed",
  failureFlash: true,
});
