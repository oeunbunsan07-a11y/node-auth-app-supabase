import { supabase } from "../config/db.ts";

// This is old_refresh token still get the access token every request

/**
 * Fetch all users registered in your custom database table.
 */
export const getAllUsersHandler = async (req: any, res: any) => {
  try {
    const { data: users, error } = await supabase
      .from("users")
      .select("id, name, email, role, is_email_verified, created_at")
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: error.message });
    }

    return res.status(200).json({
      success: true,
      data: users,
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: "Server error while fetching users.",
      error: error.message,
    });
  }
};

/**
 * Update the authorization clearance role of a specific user.
 */
export const updateUserRoleHandler = async (req: any, res: any) => {
  try {
    const { userId } = req.params;
    console.log(userId)
    const { role } = req.body;

    // Validate request inputs
    if (!role || !["user", "moderator", "admin"].includes(role)) {
      return res.status(400).json({
        success: false,
        message: "Valid role selection ('user', 'moderator', 'admin') is required.",
      });
    }

    const { data: updatedUser, error } = await supabase
      .from("users")
      .update({ role })
      .eq("id", userId)
      .select("id, name, email, role")
      .single();

    if (error) {
      return res.status(500).json({ success: false, message: error.message });
    }

    return res.status(200).json({
      success: true,
      message: "User privileges updated successfully.",
      data: updatedUser,
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: "Server error modifying user privileges.",
      error: error.message,
    });
  }
};

/**
 * Administrative removal of a user profile record.
 */
export const deleteUserHandler = async (req: any, res: any) => {
  try {
    const { userId } = req.params;

    // Prevent administrators from accidentally deleting their own active profile session
    if (req.user?.id === userId) {
      return res.status(400).json({
        success: false,
        message: "Action rejected. You cannot delete your own administrative account.",
      });
    }

    const { error } = await supabase.from("users").delete().eq("id", userId);

    if (error) {
      return res.status(500).json({ success: false, message: error.message });
    }

    return res.status(200).json({
      success: true,
      message: "User account dropped from system databases successfully.",
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: "Server error attempting user profile purge.",
      error: error.message,
    });
  }
};
