import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
  const {token} = req.cookies;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user! Token missing.",
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_TOKEN_SECRET || "default_secret"
    );
    if (decoded.id) {
      req.body.userId = decoded.id;
    } else {
      return res.json({
        success: false,
        message: "Not Authorized. Login Again",
      });
    }
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user! Invalid or expired token.",
    });
  }
};

export default authMiddleware;
