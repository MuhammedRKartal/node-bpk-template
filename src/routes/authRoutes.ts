import { Router } from "express";
import {
  changePassword,
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
router.post("/change-password", validateToken, changePassword);

router.get("/current-user", validateToken, currentUser);

export default router;
