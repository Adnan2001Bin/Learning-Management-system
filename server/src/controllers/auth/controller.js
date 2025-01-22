import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "../../models/user.model.js";
import ms from "ms";
import transporter from "../../config/nodemailer.js";

// Utility: Create JWT
const createToken = (user) => {
  const { _id, role, email, userName } = user;

  return jwt.sign(
    { id: _id, role, email, userName },
    process.env.JWT_TOKEN_SECRET || "default",
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "1h" }
  );
};

// Utility: Send Email
const sendEmail = async (options) => {
  try {
    await transporter.sendMail(options);
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("Failed to send email");
  }
};

// Utility: Validate Request Body
const validateFields = (fields, body) => {
  for (const field of fields) {
    if (!body[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }
};

// Register User
export const registerUser = async (req, res) => {
  try {
    const { userName, email, password } = req.body;

    validateFields(["userName", "email", "password"], req.body);

    // Check if user already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with this email. Please log in.",
      });
    }

    // Hash password and create user
    const hashPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ userName, email, password: hashPassword });

    await newUser.save();

    // Generate token
    const token = createToken(newUser);

    // Set cookie
    res.cookie("token" , token , {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: ms(process.env.ACCESS_TOKEN_EXPIRY || "1h"),
    })

    await sendEmail({
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to AB-TECH",
      text: `Welcome to AB-TECH! Your account has been created with email: ${email}`,
    });


    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
    });


  } catch (error) {
    console.error("Error during registration:", error);
    res.json({
      success: false,
      message: error.message || "An error occurred while registering the user.",
    });
  }
};


// Login User
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    validateFields(["email", "password"], req.body);

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found. Please register first.",
      });
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid password. Please try again.",
      });
    }

    // Generate token
    const token = createToken(user);

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: ms(process.env.ACCESS_TOKEN_EXPIRY || "1h"),
    });

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        userName: user.userName,
        email: user.email,
        role: user.role,
      },
      token,
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred while logging in.",
    });
  }
};

// Logout User
export const logoutUser = (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json({ success: true, message: "Logged out successfully." });
  } catch (error) {
    console.error("Error during logout:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred during logout.",
    });
  }
};

// Send Verification OTP
export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await User.findById(userId);
    if (!user) throw new Error("User not found");

    if (user.isAccountVerified) {
      return res.status(400).json({
        success: false,
        message: "Account already verified.",
      });
    }

    // Generate OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + ms("1d");
    await user.save();

    // Send OTP Email
    await sendEmail({
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. Use this to verify your account.`,
    });

    res.json({ success: true, message: "Verification OTP sent via email." });
  } catch (error) {
    console.error("Error during OTP generation:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred during OTP generation.",
    });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    validateFields(["userId", "otp"], req.body);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    if (!user.verifyOtp || user.verifyOtp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP." });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP has expired." });
    }

    user.isAccountVerified = true;
    user.verifyOtp = null;
    user.verifyOtpExpireAt = null;
    await user.save();

    res.json({ success: true, message: "Email verified successfully." });
  } catch (error) {
    console.error("Error during email verification:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred during email verification.",
    });
  }
};


export const sendResetOtp = async (req, res) => {
  try {
    const { email } = req.body;

    validateFields(["email"], req.body);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    // Generate OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + ms("15m");
    await user.save();

    // Send Reset OTP Email
    await sendEmail({
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP for resetting your password is ${otp}. Use this OTP within 15 minutes.`,
    });

    res.json({ success: true, message: "Reset OTP sent to your email." });
  } catch (error) {
    console.error("Error during reset OTP generation:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred while sending reset OTP.",
    });
  }
};


export const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    validateFields(["email", "otp", "newPassword"], req.body);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    if (!user.resetOtp || user.resetOtp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP." });
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP has expired." });
    }

    // Hash new password
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetOtp = null;
    user.resetOtpExpireAt = null;
    await user.save();

    res.json({ success: true, message: "Password reset successfully." });
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred while resetting the password.",
    });
  }
};


export const isAuthenticated = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ success: false, message: "Not authenticated." });
    }

    const decoded = jwt.verify(token, process.env.JWT_TOKEN_SECRET || "default_secret");
    if (!decoded) {
      return res.status(401).json({ success: false, message: "Invalid token." });
    }

    res.json({ success: true, message: "User is authenticated.", userId: decoded.id });
  } catch (error) {
    console.error("Error during authentication check:", error);
    res.status(500).json({
      success: false,
      message: error.message || "An error occurred during authentication check.",
    });
  }
};

