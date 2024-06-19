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

// Serve registration page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, './', 'register.html'));
});

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


// Manually add admin user (one-time operation)
const addAdminUser = async () => {
  try {
    const admin = new Admin({
      fullName: 'Edith Akporero',
      phone: '9030155327',
      username: 'Admin',
      email: 'akporeroedith96@gmail.com',
      password: 'Admin.1234',
    });
    await admin.save();
    console.log("Admin user created");
  } catch (error) {
    console.log("Error creating admin user:", error);
  }
};

// Uncomment the following line and run the server once to add the admin user

//addAdminUser();




const generateCouponCode = () => crypto.randomBytes(4).toString("hex");

app.post('/generate-coupon', async (req, res) => {
  try {
    const { value, currency } = req.body;
    const newCoupon = new Coupon({
      code: generateCouponCode(),
      value,
      currency,
    });

    await newCoupon.save();
    res.status(200).json({ message: 'Coupon generated successfully', coupon: newCoupon });
  } catch (error) {
    console.error('Error generating coupon:', error);
    res.status(500).json({ message: 'Failed to generate coupon' });
  }
});

app.post('/mark-coupon-used', async (req, res) => {
  try {
    const { code } = req.body;
    const coupon = await Coupon.findOne({ code });
    if (!coupon || !coupon.isActive) {
      return res.status(400).json({ message: 'Invalid or inactive coupon code' });
    }
    
    coupon.isUsed = true;
    coupon.isActive = false;
    await coupon.save();
    res.status(200).json({ message: 'Coupon marked as used' });
  } catch (error) {
    console.error('Error marking coupon as used:', error);
    res.status(500).json({ message: 'Failed to mark coupon as used' });
  }
});




app.get('/coupons', async (req, res) => {
  try {
    const coupons = await Coupon.find();
    res.status(200).json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ message: 'Failed to fetch coupons' });
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
    const { fullName, email, phone, password, username, referralLink, couponCode } = req.body;

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

    const coupon = await Coupon.findOne({ code: couponCode });
    if (!coupon || !coupon.isActive || coupon.isUsed) {
      return res.status(400).json({ message: "Invalid or inactive coupon code" });
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
      if (referrer && referrer.referralLinkActive) {
        newUser.referredBy = referrer._id;
        referrer.referrals.push(newUser._id);

        // Credit referrer's wallet
        const amountToCredit = referrer.accountType === 'naira' ? 4000 : 4;
        referrer.wallet += amountToCredit;
        referrer.referralWallet += amountToCredit;
        await referrer.save();
      } else {
        return res.status(400).json({ message: "Invalid or inactive referral link" });
      }
    }

    await newUser.save();
    await sendVerificationEmail(newUser.email, newUser.verificationToken);

    // Mark coupon as used
    coupon.isUsed = true;
    coupon.isActive = false;
    coupon.usedBy = { email: newUser.email, username: newUser.username, phone: newUser.phone };
    await coupon.save();

    res.status(200).json({ message: "User registered successfully", userId: newUser._id });
  } catch (error) {
    console.log("Error registering user:", error);
    if (error.code === 11000) {
      return res.status(400).json({ message: "Duplicate key error", error: error.message });
    }
    res.status(500).json({ message: "Registration failed" });
  }
});

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, './')));



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


// Admin login endpoint
app.post("/login/admin", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    const admin = await Admin.findOne({
      $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }]
    });

    if (!admin || !await bcrypt.compare(password, admin.password)) {
      return res.status(401).json({ message: "Invalid username or email or password" });
    }

    const token = jwt.sign({ adminId: admin._id, role: 'admin' }, secretKey, { expiresIn: '1h' });

    res.status(200).json({ message: "Admin login successful", token });
  } catch (error) {
    console.log("Error logging in admin:", error);
    res.status(500).json({ message: "Admin login failed" });
  }
});




// Middleware to authenticate admin token
const authenticateAdminToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, admin) => {
    if (err) return res.sendStatus(403);
    req.admin = admin;
    next();
  });
};



// Example of a protected admin route
app.get('/admin/protected', authenticateAdminToken, (req, res) => {
  res.status(200).json({ message: 'This is a protected admin route' });
});




app.get("/admin-details", authenticateAdminToken, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.adminId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    res.status(200).json({
      admin: {
        fullName: admin.fullName,
        email: admin.email,
      }
    });
  } catch (error) {
    console.log("Error fetching admin details:", error);
    res.status(500).json({ message: "Error fetching admin details", error });
  }
});


// Endpoint to get the number of users
app.get('/admin/user-count', authenticateAdminToken, async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    res.status(200).json({ userCount });
  } catch (error) {
    console.error('Error fetching user count:', error);
    res.status(500).json({ message: 'Failed to fetch user count' });
  }
});

// Endpoint to fetch user details
app.get('/admin/users', authenticateAdminToken, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }); // Exclude password field
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});




