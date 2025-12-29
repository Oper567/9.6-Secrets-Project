import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { supabase } from "./supabase.js";
import { comparePassword } from "./helpers.js";

// ----- LOCAL STRATEGY -----
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const { data: users, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email.toLowerCase())
        .single();

      if (error) return done(null, false, { message: "User not found" });

      const user = users;

      if (user.password === "google-oauth") {
        return done(null, false, { message: "Use Google Sign-In" });
      }

      const valid = await comparePassword(password, user.password);
      return valid ? done(null, user) : done(null, false, { message: "Wrong password" });

    } catch (err) {
      done(err);
    }
  })
);

// ----- GOOGLE STRATEGY -----
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (token, secret, profile, done) => {
      try {
        const email = profile.emails[0].value.toLowerCase();

        // Check if user exists
        let { data: existingUser } = await supabase
          .from("users")
          .select("*")
          .eq("email", email)
          .single();

        if (existingUser) return done(null, existingUser);

        // Create new Google user
        const { data: newUser } = await supabase
          .from("users")
          .insert({ email, password: "google-oauth", role: "user", is_verified: true })
          .select()
          .single();

        return done(null, newUser);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// ----- SERIALIZE / DESERIALIZE -----
passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const { data: user, error } = await supabase.from("users").select("*").eq("id", id).single();
    if (error) return done(error);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

export default passport;
