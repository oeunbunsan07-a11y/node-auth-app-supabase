import { Router } from "express";
import { authGuard } from "../middlewares/auth-guard.ts";
import { roleGuard } from "../middlewares/role-guard.ts";
import { getAllUsersHandler, updateUserRoleHandler, deleteUserHandler } from "../controllers/admin.controller.ts";

export const adminRouter = Router();

// Apply systemic verification across ALL nested admin endpoints at once
adminRouter.use(authGuard);
adminRouter.use(roleGuard(["admin"]));

// Core Admin Routes
adminRouter.get("/users", getAllUsersHandler);
adminRouter.patch("/users/:userId/role", updateUserRoleHandler);
adminRouter.delete("/users/:userId", deleteUserHandler);