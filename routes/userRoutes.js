import express from "express";
import { isAuth } from "../middleware/authMiddleware.js";
import { getProfile, editProfile } from "../controllers/userController.js";

const router = express.Router();

router.get("/:id", isAuth, getProfile);
router.post("/:id/edit", isAuth, editProfile);

export default router;
