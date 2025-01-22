import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  userName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  verifyOtp: {
    type: String,
    default: "",
  },
  verifyOtpExpireAt: {
    type: Number,
    default: 0,
  },
  isAccountVerified: {
    type: Boolean,
    default: false,
  },
  resetOtp: {
    type: String,
    default: '',
  },
  resetOtpExpireAt: {
    type: Number,
    default: 0,
  },
  role: {
    type: String,
    default: "user",
  },
});

export const User = mongoose.models.User || mongoose.model("User", userSchema);
