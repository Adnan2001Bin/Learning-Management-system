import { User } from "../../models/user.model.js";

// Get User Data
export const getUserData = async (req, res) => {
  try {
    const { userId } = req.body;

    // Validate input
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    // Fetch user from database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    // Respond with user data
    return res.status(200).json({
      success: true,
      userData: {
        name: user.userName,
        email:user.email,
        isAccountVerified: user.isAccountVerified,
      },
    });
  } catch (error) {
    console.error("Error fetching user data:", error);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching user data.",
      error: error.message,
    });
  }
};
