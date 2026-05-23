import { Router } from "express";
import { loginHandler, registerHandler } from "../controllers/auth.controller.ts";
import { authGuard } from "../middlewares/auth-guard.ts";

export const authRouter = Router();

authRouter.post("/register", registerHandler);
authRouter.post("/login", loginHandler);

// Protected Route (Requires header -> Authorization: Bearer <your_jwt>)
authRouter.get("/me", authGuard, (req: any, res: any) => {
  // TypeScript accurately knows req.user exists because of the interface extension!
  return res.status(200).json({
    success: true,
    message: "Protected user account data retrieved successfully.",
    user: req.user, 
  });
});