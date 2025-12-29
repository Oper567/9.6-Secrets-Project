import passport from "../utils/passport.js";

// Ensure authenticated session (for web)
export const ensureAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
};

// Ensure admin user
export const ensureAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === "admin") return next();
  res.status(403).json({ message: "Admins only" });
};

// JWT Auth middleware (for API routes)
export const jwtAuth = (req, res, next) => {
  passport.authenticate("jwt", { session: false }, (err, user, info) => {
    if (err || !user) return res.status(401).json({ message: "Unauthorized" });
    req.user = user;
    next();
  })(req, res, next);
};
