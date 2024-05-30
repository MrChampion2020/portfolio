const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  wallet: { type: Number, default: 0 },
    fullName: String,
    username: { type: String, unique: true },
    phone: String,
    couponCode: String,
    packageOption: String,
    verificationCode: String,
    isVerified: { type: Boolean, default: false }
  
});

module.exports = mongoose.model('User', UserSchema);
