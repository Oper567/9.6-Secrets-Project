import express from "express";
import { isAuth } from "../middleware/authMiddleware.js";
import { getChat, sendMessage } from "../controllers/chatController.js";

const router = express.Router();

// Get chat page with a user
router.get("/:userId", isAuth, getChat);

// Send a message (can be used for AJAX or API)
router.post("/send/:userId", isAuth, sendMessage);

export default router;
