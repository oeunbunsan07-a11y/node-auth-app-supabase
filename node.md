Does the old refresh-token can response the new access token every request?Yes, with the current code setup, the old refresh token can be used multiple times to get a new access token on every single request.This happens because the string stored in your database (user.refresh_token) remains identical to the one the user passes in. Until that 7-day token expires or the user logs out, it will always pass your verification checks.Is this a security risk?Yes. If a malicious actor steals that refresh token, they can repeatedly generate access tokens and stay logged in as your user for days.How to fix it: "Refresh Token Rotation"To prevent this risk, you should implement Refresh Token Rotation. Every single time a user asks for a new accessToken, you should also generate a brand new refreshToken, save the new one to the database, and send both back to the client. This instantly invalidates the old refresh token.Here is the updated refreshTokenHandler with rotation security built-in:typescriptimport { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { supabase } from "../config/db.ts";

interface RefreshPayload {
  id: string;
}

export const refreshTokenHandler = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ success: false, message: "Refresh token is required." });
    }

    const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret || !jwtRefreshSecret) {
        throw new Error("JWT secrets misconfigured.");
    }

    // 1. Verify structure of the current token
    const decoded = jwt.verify(refreshToken, jwtRefreshSecret) as RefreshPayload;

    // 2. Fetch the user row
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, role, refresh_token")
      .eq("id", decoded.id)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ success: false, message: "User session not found." });
    }

    // 3. Detect Reuse: If the sent token doesn't match the one in the DB, 
    // it means this token was already used or revoked!
    if (user.refresh_token !== refreshToken) {
         // SECURITY BREACH WARNING: Revoke the current valid token as a safety measure
         await supabase.from("users").update({ refresh_token: null }).eq("id", user.id);
         return res.status(403).json({ success: false, message: "Breach detected. Session revoked." });
    }

    // 4. Generate a fresh Access Token
    const newAccessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      jwtSecret,
      { expiresIn: "15m" }
    );

    // 5. ROTATION: Generate a brand NEW Refresh Token
    const newRefreshToken = jwt.sign(
      { id: user.id },
      jwtRefreshSecret,
      { expiresIn: "7d" }
    );

    // 6. Overwrite the old token in the database immediately
    await supabase
      .from("users")
      .update({ refresh_token: newRefreshToken })
      .eq("id", user.id);

    // 7. Send BOTH new tokens back to the frontend
    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken // The client must replace their old stored token with this one
    });
  } catch (error: any) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired refresh token session.",
    });
  }
};
Use code with caution.How the Frontend Handles ThisYour frontend must update its storage (localStorage, SecureStore, or state) with the new refreshToken every single time it receives a successful response from your /refresh-token endpoint.If you are ready, let me know if you want to write a frontend interceptor example (like Axios) to see how the client automatically swaps these tokens, or if we should add Zod input validation to secure your API endpoints.