import express from "express";
import { isAuth } from "../middleware/authMiddleware.js";
import { getNotifications } from "../controllers/notificationController.js";

const router = express.Router();

router.get("/", isAuth, getNotifications);

export default router;
