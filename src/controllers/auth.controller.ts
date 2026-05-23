import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { supabase } from "../config/db.ts"; // Ensure this matches your actual path

export const registerHandler = async (req: any, res: any) => {
    try {
        // 1. Get the user input
        const { name, email, password }: any = req.body;

        // 2. Validate the input
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required."
            });
        }

        // 3. Check if user already exists
        // FIX: Destructured { data } and checked for potential query errors
        const { data: existingUser, error: checkError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (checkError) {
            return res.status(500).json({ success: false, message: checkError.message });
        }

        // FIX: Check if existingUser data actually exists
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists",
            });
        }

        // 4. Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 5. Create user
        // FIX: Destructured { data: user } so we can extract database columns cleanly
        const { data: user, error: insertError } = await supabase
            .from('users')
            .insert([
                {
                    email,
                    password_hash: hashedPassword,
                    name
                }
            ])
            .select()
            .single();

        if (insertError) {
            return res.status(500).json({ success: false, message: insertError.message });
        }

        // 6. Send response
        return res.status(201).json({
            success: true,
            message: "User registered successfully",
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role ?? "user", // Fallback if role defaults in DB
            },
        });
    } catch (error: any) {
        return res.status(500).json({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
};


export const loginHandler = async (req: any, res: any) => {
    try {
        const { email, password }: any = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "All fields are required." });
        }

        const { data: user, error: fetchError } = await supabase
            .from('users').select('*').eq('email', email).maybeSingle();

        if (fetchError || !user) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const jwtSecret = process.env.JWT_SECRET;
        const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
        if (!jwtSecret || !jwtRefreshSecret) {
            throw new Error("JWT environment configurations are missing.");
        }

        // 1. Generate short-lived Access Token (15 mins)
        const accessToken = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name },
            jwtSecret,
            { expiresIn: "15m" }
        );

        // 2. Generate long-lived Refresh Token (7 days)
        const refreshToken = jwt.sign(
            { id: user.id },
            jwtRefreshSecret,
            { expiresIn: "7d" }
        );

        // 3. Save the refresh token to the database column
        const { error: updateError } = await supabase
            .from('users')
            .update({ refresh_token: refreshToken })
            .eq('id', user.id);

        if (updateError) {
            return res.status(500).json({ success: false, message: "Failed to store session.", error: updateError });
        }

        // 4. Return BOTH tokens in the body
        return res.status(200).json({
            success: true,
            message: "Login successful",
            access_token: accessToken,
            refresh_token: refreshToken, // The frontend must manually store this (e.g., in localStorage or memory)
            user: { id: user.id, name: user.name, email: user.email, role: user.role },
        });
    } catch (error: any) {
        return res.status(500).json({ success: false, message: "Server error", error: error.message });
    }
};


export const refreshTokenHandler = async (req: any, res: any) => {
    try {
        const { refresh_token }: any = req.body;

        if (!refresh_token) {
            return res.status(400).json({ success: false, message: "Refresh token is required." });
        }

        const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret || !jwtRefreshSecret) {
            throw new Error("JWT secrets misconfigured.");
        }

        // 1. Verify structure of the current token
        const decoded = jwt.verify(refresh_token, jwtRefreshSecret) as any;

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
        if (user.refresh_token !== refresh_token) {
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
            access_token: newAccessToken,
            refresh_token: newRefreshToken // The client must replace their old stored token with this one
        });
    } catch (error: any) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired refresh token session.",
        });
    }
};

/**
 * Handles user logout by permanently revoking their stored refresh token.
 */
export const logoutHandler = async (req: any, res: any) => {
    try {
        // 1. Extract the token string from the request body
        const { refresh_token } : any = req.body;

        if (!refresh_token) {
            return res.status(400).json({
                success: false,
                message: "Refresh token is required to execute logout.",
            });
        }

        // 2. Clear out the database column matching this specific token
        // This renders the token completely useless if someone attempts to reuse it
        const { data, error } = await supabase
            .from("users")
            .update({ refresh_token: null })
            .eq("refresh_token", refresh_token)
            .select("id"); // Returns the affected row data if found

        if (error) {
            return res.status(500).json({
                success: false,
                message: "Database error during logout.",
                error: error.message
            });
        }

        // 3. If no rows were updated, it means the token was already invalid or rotated
        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Session not found or already logged out.",
            });
        }

        // 4. Send absolute success response
        return res.status(200).json({
            success: true,
            message: "Logged out successfully. Secure session cleared.",
        });
    } catch (error: any) {
        return res.status(500).json({
            success: false,
            message: "Server error attempting account logout.",
            error: error.message,
        });
    }
};


export const profileHandler = async (req: any, res: any) => {
    // TypeScript accurately knows req.user exists because of the interface extension!
    return res.status(200).json({
        success: true,
        message: "Protected user account data retrieved successfully.",
        user: req.user,
    });
}