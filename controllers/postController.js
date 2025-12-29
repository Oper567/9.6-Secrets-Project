import { db } from "../utils/db.js";

export const createPost = async (req, res, next) => {
  try {
    const { content } = req.body;
    const mediaUrl = req.file ? req.file.path : null;

    await db.query(
      "INSERT INTO posts (user_id, content, media_url) VALUES ($1, $2, $3)",
      [req.user.id, content, mediaUrl]
    );

    res.redirect("/feed");
  } catch (err) {
    next(err);
  }
};

export const deletePost = async (req, res, next) => {
  try {
    const { id } = req.params;
    await db.query("DELETE FROM posts WHERE id=$1 AND user_id=$2", [id, req.user.id]);
    res.redirect("/feed");
  } catch (err) {
    next(err);
  }
};
