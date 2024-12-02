import { Router } from "express";
import {
  login,
  register,
  verifyRegistration,
} from "../controllers/userController";

const router = Router();

router.post("/register", register);
router.post("/verify", verifyRegistration);
router.post("/login", login);

export default router;
