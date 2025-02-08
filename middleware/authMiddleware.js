// Protect routes for getting user data
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const protect = asyncHandler (async(req, res, next) => {
  try {
    // Forward users to login
    const token = req.cookies.token;
    
    // No token
    if (!token) {
      res.status(400);
      throw new Error("Not authorized! Please log in.");
    }

    // Verify token (with jwt secret that was created previosly)
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Get user id from token
    const user = await User.findById(verified.id).select("-password");
    if (!user) {
      res.status(404);
      throw new Error("User not found.");
    }
    if (user.role === "suspended") {
      res.status(400);
      throw new Error("User is suspended. Please contact for support!");
    }
    
    req.user = user;
    next();

  } catch (error) {
    res.status(401);
    throw new Error("Not authorized! Please log in.");
  }
});

const adminOnly = asyncHandler(async(req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized as an admin");
  }
});

const authorOnly = asyncHandler(async(req, res, next) => {
  if (req.user && (req.user.role === "author" || req.user.role === "admin")) {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized as an author or admin");
  }
});

const verifiedOnly = asyncHandler(async(req, res, next) => {
  if (req.user && req.user.isVerified) {
    next();
  } else {
    res.status(401);
    throw new Error("Unverified Account");
  }
});

module.exports = {
  protect,
  adminOnly,
  authorOnly,
  verifiedOnly,
};