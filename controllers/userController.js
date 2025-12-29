import { db } from "../utils/db.js";

export const getProfile = async (req, res, next) => {
  try {
    const { id } = req.params;
    const result = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    if (!result.rows.length) return res.redirect("/feed");

    res.render("profile", { userProfile: result.rows[0] });
  } catch (err) {
    next(err);
  }
};

export const editProfile = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { name, bio } = req.body;
    await db.query("UPDATE users SET name=$1, bio=$2 WHERE id=$3", [name, bio, id]);
    res.redirect(`/user/${id}`);
  } catch (err) {
    next(err);
  }
};
