import express from "express";
import { isAuth } from "../middleware/authMiddleware.js";
import { getFeed } from "../controllers/feedController.js";

const router = express.Router();

router.get("/", isAuth, getFeed);

export default router;
