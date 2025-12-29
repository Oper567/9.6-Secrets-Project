import { db } from "../utils/db.js";

export const getFeed = async (req, res, next) => {
  try {
    const posts = await db.query("SELECT * FROM posts ORDER BY created_at DESC");
    res.render("feed", { posts: posts.rows });
  } catch (err) {
    next(err);
  }
};
