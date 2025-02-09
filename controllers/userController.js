const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const { generateToken, hashToken } = require("../utils");
const jwt = require("jsonwebtoken");
var parser = require("ua-parser-js");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const path = require("path"); // Import the 'path' module
const fs = require("fs").promises; // Import the 'fs' promises API
const { OAuth2Client } = require("google-auth-library");

const cryptr = new Cryptr(process.env.CRYPTR_KEY);
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Sign Up
const registerUser = asyncHandler(async(req, res) => {
  const { name, email, password} = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400); // bad request
    throw new Error("Please fill in all the required fields.");
  }

  if (password.length < 6) {
    res.status(400); // bad request
    throw new Error("Password must be at least 6 characters long.");
  }

  // Check if user exists
  const userExists = await User.findOne({email});
  if (userExists) {
    res.status(400);
    throw new Error("Email has already been registered.");
  }

  // Get user-agent
  const ua = parser(req.headers['user-agent']);
  const userAgent = [ua.ua];

  // Create new user
  const user = await User.create({
    name,
    email,
    password,
    userAgent
  })

  // Generate Token
  const token = generateToken(user._id)

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 DAY
    sameSite: "none",
    secure: true,
  })

  if (user) {
    const {_id, name, email, phone, bio, photo, role, isVerified} = user;

    res.status(201).json({
      _id, name, email, phone, bio, photo, role, isVerified, token
    })
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// Send Verification Email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  if (user.isVerified) {
    res.status(400);
    throw new Error("User already verified");
  }

  // Delete token if already existed in db
  let token = await Token.findOne({ userId: user._id});
  if (token) {
    await token.deleteOne()
  }

  // Create Verification Token and Save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(verificationToken);

  // Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiredAt: Date.now() + 60 * (60 * 1000) // expire after 60 mins
  }).save();

  // Contruct a verification URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  // Send verification email
  const subject = "Verify Your Account - AuthZ Pro";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = process.env.EMAIL_USER;
  const name = user.name;
  const link = verificationUrl;
  const templateId = "d-b291077696554f609b4c9ab277264256";

  try {
    await sendEmail(
      send_to,
      sent_from,
      reply_to,
      templateId,
      {
        name: name,
        link: link,
        subject: subject
      }
    );
      
    res.status(200).json({ message: "Verification Email Sent" });
  } catch (error) {
    console.error("Email Error:", error);
    res.status(500).json({ message: "Email not sent, please try again" });
  }
});

// Send Login Code
const sendLoginCode = asyncHandler(async(req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find Login Code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiredAt: {$gt: Date.now()}
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, please log in again");
  }

  const loginCode = userToken.lToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  // Send Login Code
  const subject = "Login Access Code - AuthZ Pro";
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = process.env.EMAIL_USER;
  const name = user.name;
  const link = decryptedLoginCode;
  const templateId = "d-626b1aa578cd4bdaa06964df145b8c45";

  try {
    await sendEmail(
      send_to,
      sent_from,
      reply_to,
      templateId,
      {
        name: name,
        link: link,
        subject: subject
      }
    );
    
    res.status(200).json({ message: `Access code sent to ${email}` });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// Verify User
const verifyUser = asyncHandler(async(req, res) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);
  const userToken = await Token.findOne({
    vToken: hashedToken,
    expiredAt: {$gt: Date.now()}
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find User
  const user = await User.findOne({
    _id: userToken.userId
  })

  if (user.isVerified) {
    res.status(400);
    throw new Error("User is already verified");
  }

  // Verify User now
  user.isVerified = true;
  await user.save();
  res.status(200).json({
    message: "Account Verified Successfully!"
  });
});

// Fixed loginUser function with proper flow
const loginUser = asyncHandler(async(req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400);
    throw new Error("Please add your email and password.");
  }

  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("User not found, please sign up.");
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);
  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("Invalid email or password.");
  }

  // Check user agent
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;
  const allowedAgent = user.userAgent.includes(thisUserAgent);

  if (!allowedAgent) {
    // Handle unknown device login
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    // Save login code
    await Token.findOneAndDelete({ userId: user._id });

    await new Token({
      userId: user._id,
      lToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiredAt: Date.now() + 60 * (60 * 1000)
    }).save();

    res.status(400);
    throw new Error("New browser or device detected.");
  }

  // Known device - proceed with login
  const token = generateToken(user._id);
  
  if (user && passwordIsCorrect) {
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      sameSite: "none", 
      secure: true,
    });
  
    res.status(200).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      bio: user.bio,
      photo: user.photo,
      role: user.role,
      isVerified: user.isVerified,
      token
    });
  }
});

const loginWithCode = asyncHandler(async(req, res) => {
  const {email} = req.params;
  const {loginCode} = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find user login token
  const userToken = await Token.findOne({
    userId: user._id,
    expiredAt: { $gt: Date.now() }
  })

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token. Please log in again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.lToken);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    // Register User Agent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;

    user.userAgent.push(thisUserAgent);
    await user.save();

    // Delete used token
    await userToken.deleteOne();

    // Generate Token
    const token = generateToken(user._id)

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 DAY
      sameSite: "none",
      secure: true,
    })

    
    const {_id, name, email, phone, bio, photo, role, isVerified} = user;
    res.status(201).json({
        _id, name, email, phone, bio, photo, role, isVerified, token
    })
  }
});

// Log Out
const logoutUser = asyncHandler(async(req, res) => {
  res.cookie("token", "", { // make token "empty string"
    path: "/",
    httpOnly: true,
    expires: new Date(0), // Expire immediately
    sameSite: "none",
    secure: true,
  })

  return res.status(200).json({message: "Logout successful"});
})

// Get User
const getUser = asyncHandler(async(req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const {_id, name, email, phone, bio, photo, role, isVerified} = user;
    res.status(200).json({
      _id, name, email, phone, bio, photo, role, isVerified
    });
  } else {
    res.status(404);
    throw new Error("User not found!");
  }
})

// Update User
const updateUser = asyncHandler(async(req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const {_id, name, email, phone, bio, photo, role, isVerified} = user;
    
    user.name = req.body.name || name;
    user.email = email;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;
    user.role = req.body.role || role;

    // Save the updated user information
    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    })
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
})

// Delete User
const deleteUser = asyncHandler(async(req, res) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("User not found, please sign up.")
  }

  res.status(200).json({
    message: "User deleted successfully"
  });
})

// Get All Users
const getUsers = asyncHandler(async(req, res) => {
  const users = await User.find().sort("-createdAt").select("-password");

  if (!users) {
    res.status(500);
    throw new Error("Something went wrong. Please try again.");
  }

  res.status(200).json(users);
})

// Get Login Status
const loginStatus = asyncHandler(async(req, res) => {
  const token = req.cookies.token;

  // User hasn't logged in
  if (!token) {
    return res.json(false);
  }

  // Verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
})

// Change User's Role
const upgradeUser = asyncHandler(async(req, res) => {
  const { role, id } = req.body;

  const user = await User.findById(id);
  if (!user) {
    res.status(404);
    throw new Error("User not found. Please sign up!");
  }

  user.role = role;
  await user.save();

  res.status(200).json({
    message: `User role updated to ${role}`,
  })
})

// Send Automated emails
const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, templateId, url } = req.body;

  if (!subject || !send_to || !reply_to || !templateId) {
    return res.status(400).json({ message: "Missing email parameter" });
  }

  // Get user
  const user = await User.findOne({ email: send_to });

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;

  try {
    await sendEmail(
      send_to,
      sent_from,
      reply_to,
      templateId,
      {
        name: name,
        link: link,
        subject: subject
      }
    );
    
    res.status(200).json({ message: "Email Sent" });
  } catch (error) {
    console.error("Email Error:", error);
    res.status(500).json({ message: "Email not sent, please try again" });
  }
});

// Forgot Password
const forgotPassword = asyncHandler(async(req, res) => {
  const { email } = req.body;
  const user = await User.findOne({email});

  if (!user) {
    res.status(404);
    throw new Error("No user with this email");
  }

  // Delete token if already existed in db
  let token = await Token.findOne({ userId: user._id});
  if (token) {
    await token.deleteOne();
  }

  // Create Reset Token and Save
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // Hash token 
  const hashedToken = hashToken(resetToken);
  
  // Save token to database
  try {
    await new Token({
      userId: user._id,
      rToken: hashedToken,
      createdAt: Date.now(),
      expiredAt: Date.now() + 60 * (60 * 1000) // 1 hour in milliseconds
    }).save();

    // Construct Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Send Reset email
    const subject = "Reset Your Password - AuthZ Pro";
    const send_to = user.email;
    const reply_to = process.env.EMAIL_USER;
    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = resetUrl;
    const templateId = "d-33cdce477c4a4e9b9c45ce36a4a806cf";

    await sendEmail(
      send_to,
      sent_from,
      reply_to,
      templateId,
      {
        name: name,
        link: link,
        subject: subject
      }
    );

    res.status(200).json({ message: "Password Reset Email Sent" });
  } catch (error) {
    console.error("Token/Email Error:", error);
    res.status(500).json({ message: "Error occurred. Please try again" });
  }
});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;
  console.log(resetToken);
  console.log(password);

  const hashedToken = hashToken(resetToken);

  const userToken = await Token.findOne({
    rToken: hashedToken,
    expiredAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find User
  const user = await User.findOne({ _id: userToken.userId });

  // Now Reset password
  user.password = password;
  await user.save();

  res.status(200).json({ message: "Password Reset Successful, please login" });
});

const changePassword = asyncHandler(async(req, res) => {
  const { oldPassword, password } =req.body

  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Bad request. Please enter old and new password");
  }

  // Check if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // Save new password
  if (user && passwordIsCorrect) {
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user.password = hashedPassword;
    await user.save();
    res.status(200).json({
      message: "Password changed succesfully, please re-login.",
    })
  } else {
    res.status(400);
    throw new Error("Old password is incorrect.")
  }
});

const loginWithGoogle = asyncHandler(async(req, res) => {
  const { userToken } = req.body;
  //console.log(userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID
  });

  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;
  //console.log(payload);

  // Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // Check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    //   Create new user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      // Generate Token
      const token = generateToken(newUser._id);

      // Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      });

      const { _id, name, email, phone, bio, photo, role, isVerified } = newUser;

      res.status(201).json({
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        token,
      });
    }
  }

  // User already existed -> Login
  if (user) {
    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
})

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle
}