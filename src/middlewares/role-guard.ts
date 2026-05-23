
/**
 * Middleware factory to restrict endpoint access based on user roles.
 * @param allowedRoles Array of strings representing roles permitted to access the route.
 */
export const roleGuard = (allowedRoles: string[]) => {
  return (req: any, res: any, next: any) => {
    try {
      // 1. Ensure the authGuard has already validated the user session
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized. Authentication context missing.",
        });
      }

      // 2. Check if the user's role matches any of the permitted roles
      const hasPermission = allowedRoles.includes(req.user.role);

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          message: "Forbidden. You do not have the required permissions to access this resource.",
        });
      }

      // 3. User passes checks, proceed safely
      return next();
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: "Internal server error within authorization guard.",
        error: error.message,
      });
    }
  };
};
