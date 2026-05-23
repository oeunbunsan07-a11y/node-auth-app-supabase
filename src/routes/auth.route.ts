import { Router } from "express";
import { loginHandler, registerHandler, profileHandler, refreshTokenHandler, logoutHandler } from "../controllers/auth.controller.ts";
import { authGuard } from "../middlewares/auth-guard.ts";

export const authRouter = Router();

authRouter.post("/register", registerHandler);
authRouter.post("/login", loginHandler);
authRouter.post("/refresh", refreshTokenHandler);
authRouter.post("/logout", logoutHandler);

// Protected Route (Requires header -> Authorization: Bearer <your_jwt>)
authRouter.get("/profile", authGuard, profileHandler);