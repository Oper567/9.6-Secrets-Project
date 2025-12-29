import express from "express";
import { isAuth } from "../middleware/authMiddleware.js";
import { upload } from "../middleware/uploadMiddleware.js";
import { createPost, deletePost } from "../controllers/postController.js";

const router = express.Router();

router.post("/create", isAuth, upload.single("media"), createPost);
router.delete("/delete/:id", isAuth, deletePost);

export default router;
