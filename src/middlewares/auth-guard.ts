import jwt from "jsonwebtoken";
//  implement a standard JWT authentication middleware

// 1. Extend the Express Request interface to securely hold user payload
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: string;
      };
    }
  }
}

interface JwtPayload {
  id: string;
  email: string;
  role: string;
}

/**
 * Middleware guard to protect private API endpoints via JWT.
 */
export const authGuard = async (
  req: any,
  res: any,
  next: any
) => {
  try {
    // 2. Extract authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Access denied. No token provided.",
      });
    }

    // 3. Isolate token string (Get the raw token)
    const token = authHeader.split(" ")[1];

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error("JWT_SECRET is not configured in the environment.");
    }

    // 4. Verify token authenticity
    const decoded = jwt.verify(token, jwtSecret) as JwtPayload;

    // 5. Attach decoded payload information straight to the request lifecycle
    req.user = {
      id: decoded.id,
      email: decoded.email,
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
      message: "Unauthorized. Invalid token token details.",
    });
  }
};
