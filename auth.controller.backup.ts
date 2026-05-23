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
        // 1. Collect the user input
        const { email, password }: any = req.body;

        // 2. Validate the input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required."
            });
        }

        // 3. Find user
        // FIX: Destructured { data: user, error } to correctly extract the table row
        const { data: user, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (fetchError) {
            return res.status(500).json({ success: false, message: fetchError.message });
        }

        // FIX: Check if the actual 'user' data payload is missing
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials",
            });
        }

        // 4. Compare password
        // FIX: user.password_hash can now be safely accessed from the destructured data
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials", // Standard secure message instead of "Wrong password"
            });
        }

        // Ensure JWT Secret is present before signing
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
            throw new Error("JWT_SECRET is missing from your environment variables.");
        }

        // 5. Generate JWT
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                role: user.role,
                name : user.name,
            },
            jwtSecret,
            {
                expiresIn: "7d",
            }
        );

        // 6. Send response
        return res.status(200).json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                is_email_verified: user.is_email_verified,
                two_factor_enabled: user.two_factor_enabled,
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

export const profileHandler = async (req: any, res: any) => {
    // TypeScript accurately knows req.user exists because of the interface extension!
    return res.status(200).json({
        success: true,
        message: "Protected user account data retrieved successfully.",
        user: req.user,
    });
}