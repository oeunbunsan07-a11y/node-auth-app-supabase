import express from "express";
import dotenv from "dotenv";
import { authRouter } from "./routes/auth.route.ts";
import { adminRouter } from "./routes/admin.route.ts";

// 1. Load environment variables before initializing the app
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;

// 2. Standard Middlewares
app.use(express.json()); // Corrected from app.use(express())

// 3. Routes
app.get("/health", (req: any, res: any) => {
    return res.status(201).json({
        success : true,
        status : "ok"
    })
});

app.use("/api/auth", authRouter);
app.use("/api/dashboard/admin", adminRouter);

// 4. Server Initialization
app.listen(PORT, () => {
  console.log(`[server]: Server is running at http://localhost:${PORT}`);
});
