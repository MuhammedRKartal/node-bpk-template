import { Router } from "express";
import {
  currentUser,
  login,
  register,
  verifyRegistration,
} from "../controllers/authController";
import { validateToken } from "../authMiddleware";

const router = Router();

router.post("/register", register);
router.post("/verify", verifyRegistration);
router.post("/login", login);
router.get("/current-user", validateToken, currentUser);

export default router;
