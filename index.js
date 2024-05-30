const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
dotenv.config();

const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI, {
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));


app.use('/auth', require('./routes/auth'));
app.use('/wallet', require('./routes/wallet'));

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html', 'register.html', 'login.html', 'dashboard.html'));
});



// Registration endpoint
app.post('/register', async (req, res) => {
  const { fullName, email, username, password, phone, couponCode, packageOption } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate verification code
    const verificationCode = crypto.randomBytes(20).toString('hex');

    // Create the user
    const user = new User({
      fullName,
      email,
      username,
      password: hashedPassword,
      phone,
      couponCode,
      packageOption,
      verificationCode
    });

    await user.save();

    // Send verification email
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Account Verification',
      text: `Please verify your account by clicking the following link: http://localhost:3000/verify/${verificationCode}`
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({ message: 'User registered successfully. Please check your email for verification.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Verification endpoint
app.get('/verify/:code', async (req, res) => {
  const { code } = req.params;

  try {
    const user = await User.findOne({ verificationCode: code });

    if (!user) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    user.isVerified = true;
    user.verificationCode = undefined;
    await user.save();

    res.status(200).json({ message: 'Account verified successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
