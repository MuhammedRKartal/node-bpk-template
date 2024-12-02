import { Router } from "express";
import { register, verifyRegistration } from "../controllers/userController";

const router = Router();

router.post("/register", register);
router.post("/verify", verifyRegistration);

export default router;
