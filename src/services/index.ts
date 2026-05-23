import { supabase } from "../config/db.js";

// Function to test the Supabase connection
export const testConnection = async () => {
  try {
    // This fetches the current API configuration/health status from Supabase
    const { data, error } = await supabase.auth.getSession();

    if (error) {
      console.error("❌ Supabase connection failed:", error.message);
      return;
    }

    console.log("✅ Supabase connection established successfully!");
  } catch (err) {
    console.error("❌ Unexpected error while connecting to Supabase:", err);
  }
};
