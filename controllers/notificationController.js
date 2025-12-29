import { db } from "../utils/db.js";

export const getNotifications = async (req, res, next) => {
  try {
    const notifications = await db.query(
      "SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.render("notifications", { notifications: notifications.rows });
  } catch (err) {
    next(err);
  }
};
