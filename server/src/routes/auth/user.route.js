import express from "express";
import authMiddleware from "../../controllers/authMiddleware.js";
import { getUserData } from "../../controllers/auth/user.controller.js";

const userRouter = express.Router();

userRouter.get("/data", authMiddleware, getUserData);

export default userRouter;
