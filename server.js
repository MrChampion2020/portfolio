const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const { ObjectId } = mongoose.Types;
const User = require("./models/User");
const Coupon = require("./models/Coupon");
const Vendor = require("./models/Vendor");
const Admin = require("./models/Admin");

app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './')));

const generateSecretKey = () => crypto.randomBytes(32).toString("hex");
const secretKey = process.env.SECRET_KEY || generateSecretKey();

mongoose.connect(process.env.MONGO_URI, {})
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.log("Error connecting to MongoDB:", error));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};




// Generate coupon endpoint
app.post('/generate-coupon', authenticateToken, async (req, res) => {
  try {
    const { userId, currency } = req.body;
    const value = currency === 'Naira' ? 5000 : 5;

    const newCoupon = new Coupon({
      code: generateCouponCode(),
      value,
      currency,
      userId: mongoose.Types.ObjectId(userId) // Convert userId to ObjectId
    });

    await newCoupon.save();
    res.status(200).json({ message: 'Coupon generated successfully', coupon: newCoupon });
  } catch (error) {
    console.log('Error generating coupon:', error);
    res.status(500).json({ message: 'Failed to generate coupon' });
  }
});



const sendVerificationEmail = async (email, verificationToken) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const API_URL = process.env.API_URL;
  const mailOptions = {
    from: "Elitearn",
    to: email,
    subject: "Email Verification",
    html: `<p>Please click on the following link to verify your email: <a href="${API_URL}/verify/${verificationToken}">${API_URL}/verify/${verificationToken}</a></p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("Error sending the verification email:", error);
  }
};

const distributeReferralBonus = async (userId, level) => {
  if (level > 1) {
    const user = await User.findById(userId);
    if (user && user.referredBy) {
      const referrer = await User.findById(user.referredBy);
      if (referrer) {
        referrer.wallet += 100;
        referrer.referralWallet += 100;
        await referrer.save();
        await distributeReferralBonus(referrer._id, level - 1);
      }
    }
  }
};

app.post("/register", async (req, res) => {
  try {
    const { fullName, email, phone, password, username, referralLink } = req.body;

    if (!username) {
      return res.status(400).json({ message: "Username is required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      fullName,
      email,
      phone,
      password: hashedPassword,
      username,
      verificationToken: crypto.randomBytes(20).toString("hex"),
    });

    // Generate referral link
    newUser.referralLink = `${process.env.API_URL}/register?ref=${username}`;

    if (referralLink) {
      const referrer = await User.findOne({ username: referralLink });
      if (referrer) {
        newUser.referredBy = referrer._id;
        referrer.referrals.push(newUser._id);
        referrer.wallet += 4000;
        referrer.referralWallet += 4000;
        await referrer.save();

        await distributeReferralBonus(referrer._id, 2);
      }
    }

    await newUser.save();
    await sendVerificationEmail(newUser.email, newUser.verificationToken);

    res.status(200).json({ message: "User registered successfully", userId: newUser._id });
  } catch (error) {
    console.log("Error registering user:", error);
    if (error.code === 11000) {
      return res.status(400).json({ message: "Duplicate key error", error: error.message });
    }
    res.status(500).json({ message: "Registration failed" });
  }
});

app.get("/verify/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid verification token" });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log("Error verifying email:", error);
    res.status(500).json({ message: "Email verification failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in user:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/user-details", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      user: {
        fullName: user.fullName,
        email: user.email,
        username: user.username,
        phone: user.phone,
        wallet: user.wallet,
        referralWallet: user.referralWallet,
        referrals: user.referrals,
        referralLink: user.referralLink,
      }
    });
  } catch (error) {
    console.log("Error fetching user details:", error);
    res.status(500).json({ message: "Error fetching user details", error });
  }
});


const authenticateAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  next();
};

app.post("/register/vendor", authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const existingVendor = await Vendor.findOne({ email });
    if (existingVendor) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newVendor = new Vendor({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    await newVendor.save();

    res.status(200).json({ message: "Vendor registered successfully", vendorId: newVendor._id });
  } catch (error) {
    console.log("Error registering vendor:", error);
    res.status(500).json({ message: "Vendor registration failed" });
  }
});

app.post("/login/vendor", async (req, res) => {
  try {
    const { email, password } = req.body;
    const vendor = await Vendor.findOne({ email });

    if (!vendor || !await bcrypt.compare(password, vendor.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!vendor.isApproved) {
      return res.status(403).json({ message: "Vendor not approved" });
    }

    const token = jwt.sign({ vendorId: vendor._id, role: "vendor" }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in vendor:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.post("/login/admin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin || !await bcrypt.compare(password, admin.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ adminId: admin._id, role: "admin" }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in admin:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/admin", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.sendStatus(403);
  }
  res.sendFile(path.join(__dirname, "admin_dashboard.html"));
});

app.get("/vendor", authenticateToken, (req, res) => {
  if (req.user.role !== "vendor") {
    return res.sendStatus(403);
  }
  res.sendFile(path.join(__dirname, "vendor_dashboard.html"));
});

const generateCouponCode = () => {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return code;
};



/*
const authenticateAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  next();
};

const authenticateVendor = (req, res, next) => {
  if (req.user.role !== 'vendor') {
    return res.sendStatus(403);
  }
  next();
};

// Admin and vendor routes
app.get('/admin', authenticateToken, authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/vendor', authenticateToken, authenticateVendor, (req, res) => {
  res.sendFile(path.join(__dirname, 'vendor.html'));
});*/

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});





/*const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const { ObjectId } = mongoose.Types;
const User = require("./models/User");
const Coupon = require("./models/Coupon");
const Vendor = require("./models/Vendor");
const Admin = require("./models/Admin");

app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './')));

const generateSecretKey = () => crypto.randomBytes(32).toString("hex");
const secretKey = process.env.SECRET_KEY || generateSecretKey();

mongoose.connect(process.env.MONGO_URI, {})
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.log("Error connecting to MongoDB:", error));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};


// Generate coupon endpoint
app.post('/generate-coupon', authenticateToken, async (req, res) => {
  try {
    const { vendorId, currency } = req.body;
    const value = currency === 'Naira' ? 5000 : 5;

    const newCoupon = new Coupon({
      code: generateCouponCode(),
      value,
      currency,
      vendorId: mongoose.Types.ObjectId(vendorId) // Convert vendorId to ObjectId
    });

    await newCoupon.save();
    res.status(200).json({ message: 'Coupon generated successfully', coupon: newCoupon });
  } catch (error) {
    console.log('Error generating coupon:', error);
    res.status(500).json({ message: 'Failed to generate coupon' });
  }
});

const sendVerificationEmail = async (email, verificationToken) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const API_URL = process.env.API_URL;
  const mailOptions = {
    from: "Elitearn",
    to: email,
    subject: "Email Verification",
    html: `<p>Please click on the following link to verify your email: <a href="${API_URL}/verify/${verificationToken}">${API_URL}/verify/${verificationToken}</a></p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("Error sending the verification email:", error);
  }
};

const distributeReferralBonus = async (userId, level) => {
  if (level > 1) {
    const user = await User.findById(userId);
    if (user && user.referredBy) {
      const referrer = await User.findById(user.referredBy);
      if (referrer) {
        referrer.wallet += 100;
        referrer.referralWallet += 100;
        await referrer.save();
        await distributeReferralBonus(referrer._id, level - 1);
      }
    }
  }
};

app.post("/register", async (req, res) => {
  try {
    const { fullName, email, phone, password, username, referralLink } = req.body;

    if (!username) {
      return res.status(400).json({ message: "Username is required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      fullName,
      email,
      phone,
      password: hashedPassword,
      username,
      verificationToken: crypto.randomBytes(20).toString("hex"),
    });

    // Generate referral link
    newUser.referralLink = `${process.env.API_URL}/register?ref=${username}`;

    if (referralLink) {
      const referrer = await User.findOne({ username: referralLink });
      if (referrer) {
        newUser.referredBy = referrer._id;
        referrer.referrals.push(newUser._id);
        referrer.wallet += 4000;
        referrer.referralWallet += 4000;
        await referrer.save();

        await distributeReferralBonus(referrer._id, 2);
      }
    }

    await newUser.save();
    await sendVerificationEmail(newUser.email, newUser.verificationToken);

    res.status(200).json({ message: "User registered successfully", userId: newUser._id });
  } catch (error) {
    console.log("Error registering user:", error);
    if (error.code === 11000) {
      return res.status(400).json({ message: "Duplicate key error", error: error.message });
    }
    res.status(500).json({ message: "Registration failed" });
  }
});

app.get("/verify/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid verification token" });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log("Error verifying email:", error);
    res.status(500).json({ message: "Email verification failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in user:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/user-details", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      user: {
        fullName: user.fullName,
        email: user.email,
        username: user.username,
        phone: user.phone,
        wallet: user.wallet,
        referralWallet: user.referralWallet,
        referrals: user.referrals,
        referralLink: user.referralLink,
      }
    });
  } catch (error) {
    console.log("Error fetching user details:", error);
    res.status(500).json({ message: "Error fetching user details", error });
  }
});



const authenticateAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  next();
};

app.post("/register/vendor", authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const existingVendor = await Vendor.findOne({ email });
    if (existingVendor) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newVendor = new Vendor({
      name,
      email,
      phone,
      password: hashedPassword,
    });

    await newVendor.save();

    res.status(200).json({ message: "Vendor registered successfully", vendorId: newVendor._id });
  } catch (error) {
    console.log("Error registering vendor:", error);
    res.status(500).json({ message: "Vendor registration failed" });
  }
});

app.post("/login/vendor", async (req, res) => {
  try {
    const { email, password } = req.body;
    const vendor = await Vendor.findOne({ email });

    if (!vendor || !await bcrypt.compare(password, vendor.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!vendor.isApproved) {
      return res.status(403).json({ message: "Vendor not approved" });
    }

    const token = jwt.sign({ vendorId: vendor._id, role: "vendor" }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in vendor:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.post("/login/admin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin || !await bcrypt.compare(password, admin.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ adminId: admin._id, role: "admin" }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in admin:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/admin", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.sendStatus(403);
  }
  res.sendFile(path.join(__dirname, "admin_dashboard.html"));
});

app.get("/vendor", authenticateToken, (req, res) => {
  if (req.user.role !== "vendor") {
    return res.sendStatus(403);
  }
  res.sendFile(path.join(__dirname, "vendor_dashboard.html"));
});

const generateCouponCode = () => {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return code;
};

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

*/




/*const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const { ObjectId } = mongoose.Types;
const User = require("./models/User");
const Coupon = require("./models/Coupon");

app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, './')));

const generateSecretKey = () => crypto.randomBytes(32).toString("hex");
const secretKey = process.env.SECRET_KEY || generateSecretKey();

mongoose.connect(process.env.MONGO_URI, {})
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.log("Error connecting to MongoDB:", error));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};




// Generate coupon endpoint
app.post('/generate-coupon', authenticateToken, async (req, res) => {
  try {
    const { userId, currency } = req.body;
    const value = currency === 'Naira' ? 5000 : 5;

    const newCoupon = new Coupon({
      code: generateCouponCode(),
      value,
      currency,
      userId: mongoose.Types.ObjectId(userId) // Convert userId to ObjectId
    });

    await newCoupon.save();
    res.status(200).json({ message: 'Coupon generated successfully', coupon: newCoupon });
  } catch (error) {
    console.log('Error generating coupon:', error);
    res.status(500).json({ message: 'Failed to generate coupon' });
  }
});



const sendVerificationEmail = async (email, verificationToken) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const API_URL = process.env.API_URL;
  const mailOptions = {
    from: "Elitearn",
    to: email,
    subject: "Email Verification",
    html: `<p>Please click on the following link to verify your email: <a href="${API_URL}/verify/${verificationToken}">${API_URL}/verify/${verificationToken}</a></p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("Error sending the verification email:", error);
  }
};

const distributeReferralBonus = async (userId, level) => {
  if (level > 1) {
    const user = await User.findById(userId);
    if (user && user.referredBy) {
      const referrer = await User.findById(user.referredBy);
      if (referrer) {
        referrer.wallet += 100;
        referrer.referralWallet += 100;
        await referrer.save();
        await distributeReferralBonus(referrer._id, level - 1);
      }
    }
  }
};

app.post("/register", async (req, res) => {
  try {
    const { fullName, email, phone, password, username, referralLink } = req.body;

    if (!username) {
      return res.status(400).json({ message: "Username is required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      fullName,
      email,
      phone,
      password: hashedPassword,
      username,
      verificationToken: crypto.randomBytes(20).toString("hex"),
    });

    // Generate referral link
    newUser.referralLink = `${process.env.API_URL}/register?ref=${username}`;

    if (referralLink) {
      const referrer = await User.findOne({ username: referralLink });
      if (referrer) {
        newUser.referredBy = referrer._id;
        referrer.referrals.push(newUser._id);
        referrer.wallet += 4000;
        referrer.referralWallet += 4000;
        await referrer.save();

        await distributeReferralBonus(referrer._id, 2);
      }
    }

    await newUser.save();
    await sendVerificationEmail(newUser.email, newUser.verificationToken);

    res.status(200).json({ message: "User registered successfully", userId: newUser._id });
  } catch (error) {
    console.log("Error registering user:", error);
    if (error.code === 11000) {
      return res.status(400).json({ message: "Duplicate key error", error: error.message });
    }
    res.status(500).json({ message: "Registration failed" });
  }
});

app.get("/verify/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid verification token" });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log("Error verifying email:", error);
    res.status(500).json({ message: "Email verification failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log("Error logging in user:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/user-details", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      user: {
        fullName: user.fullName,
        email: user.email,
        username: user.username,
        phone: user.phone,
        wallet: user.wallet,
        referralWallet: user.referralWallet,
        referrals: user.referrals,
        referralLink: user.referralLink,
      }
    });
  } catch (error) {
    console.log("Error fetching user details:", error);
    res.status(500).json({ message: "Error fetching user details", error });
  }
});

const authenticateAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  next();
};

const authenticateVendor = (req, res, next) => {
  if (req.user.role !== 'vendor') {
    return res.sendStatus(403);
  }
  next();
};

// Admin and vendor routes
app.get('/admin', authenticateToken, authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/vendor', authenticateToken, authenticateVendor, (req, res) => {
  res.sendFile(path.join(__dirname, 'vendor.html'));
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
*/
