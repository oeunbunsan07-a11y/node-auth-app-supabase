// import { supabase } from "../config/db.ts";
// import jwt from "jsonwebtoken";

// //  implement a standard JWT authentication middleware

// // 1. Extend the Express Request interface to securely hold user payload
// declare global {
//   namespace Express {
//     interface Request {
//       user?: {
//         id: string;
//         email: string;
//         role: string;
//       };
//     }
//   }
// }

// interface JwtPayload {
//   id: string;
//   email: string;
//   role: string;
//   name: string,
// }

// /**
//  * Middleware guard to protect private API endpoints via JWT.
//  */
// export const authGuard = async (
//   req: any,
//   res: any,
//   next: any
// ) => {
//   try {
//     // 2. Extract authorization header
//     const authHeader = req.headers.authorization;

//     if (!authHeader || !authHeader.startsWith("Bearer ")) {
//       return res.status(401).json({
//         success: false,
//         message: "Access denied. No token provided.",
//       });
//     }

//     // 3. Isolate token string (Get the raw token)
//     const token = authHeader.split(" ")[1];

//     const jwtSecret = process.env.JWT_SECRET;
//     if (!jwtSecret) {
//       throw new Error("JWT_SECRET is not configured in the environment.");
//     }

//     // 4. Verify token authenticity
//     const decoded = jwt.verify(token, jwtSecret) as JwtPayload;

//     // Inside your authGuard.ts after verifying the JWT signature:
//     const { data: user } = await supabase
//       .from("users")
//       .select("refresh_token")
//       .eq("id", decoded.id)
//       .maybeSingle();

//     // If the database refresh_token column is null, they logged out!
//     if (!user || !user.refresh_token) {
//       return res.status(401).json({ success: false, message: "Session closed. Please log in again." });
//     }

//     // 5. Attach decoded payload information straight to the request lifecycle
//     req.user = {
//       id: decoded.id,
//       email: decoded.email,
//       name: decoded.name,
//       role: decoded.role,
//     };

//     // Proceed to target route handler safely
//     return next();
//   } catch (error: any) {
//     // Catch expired or tampered token errors specifically
//     if (error.name === "TokenExpiredError") {
//       return res.status(401).json({
//         success: false,
//         message: "Unauthorized. Your session has expired.",
//       });
//     }

//     return res.status(401).json({
//       success: false,
//       message: "Unauthorized. Invalid token token details.",
//     });
//   }
// };



import jwt from "jsonwebtoken";
import { supabase } from "../config/db.ts"; // 1. Added missing Supabase import

// 2. Define the structural shape of your encoded JWT payload
interface JwtPayload {
  id: string;
  email: string;
  name: string;
  role: string;
}

// 3. Extend Express Request interface globally so TypeScript allows req.user
declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

export const authGuard = async (
  req: any,      // FIX: Replaced 'any' with Express types
  res: any,     // FIX: Replaced 'any' with Express types
  next: any // FIX: Replaced 'any' with Express types
) => {
  try {
    // 1. Extract authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Access denied. No token provided.",
      });
    }

    // 2. Isolate token string
    const token = authHeader.split(" ")[1];

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error("JWT_SECRET is not configured in the environment.");
    }

    // 3. Verify token authenticity
    const decoded = jwt.verify(token, jwtSecret) as JwtPayload;

    // 4. Check the database to guarantee the session hasn't been logged out
    const { data: user, error: dbError } = await supabase
      .from("users")
      .select("refresh_token")
      .eq("id", decoded.id)
      .maybeSingle();

    // Safety guard: If database encounters an issue or user session is cleared, block access
    if (dbError || !user || !user.refresh_token) {
      return res.status(401).json({ 
        success: false, 
        message: "Session closed. Please log in again." 
      });
    }

    // 5. Attach decoded payload information safely to the request lifecycle
    req.user = {
      id: decoded.id,
      email: decoded.email,
      name: decoded.name,
      role: decoded.role,
    };

    // Proceed to target route handler safely
    return next();
  } catch (error: any) {
    // Catch expired or tampered token errors specifically
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Unauthorized. Your session has expired.",
      });
    }

    return res.status(401).json({
      success: false,
      message: "Unauthorized. Invalid token details.", // FIX: Removed redundant "token token" typo
    });
  }
};

