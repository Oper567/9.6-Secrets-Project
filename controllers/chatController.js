import { db } from "../utils/db.js";

export const getChat = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const messages = await db.query(
      `SELECT * FROM messages 
       WHERE (sender_id=$1 AND receiver_id=$2) 
          OR (sender_id=$2 AND receiver_id=$1)
       ORDER BY created_at ASC`,
      [req.user.id, userId]
    );

    const otherUser = await db.query("SELECT id, name, email FROM users WHERE id=$1", [userId]);
    res.render("chat", { messages: messages.rows, otherUser: otherUser.rows[0] });
  } catch (err) {
    next(err);
  }
};

export const sendMessage = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { message } = req.body;

    await db.query(
      "INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1, $2, $3)",
      [req.user.id, userId, message]
    );

    res.status(200).json({ success: true });
  } catch (err) {
    next(err);
  }
};
