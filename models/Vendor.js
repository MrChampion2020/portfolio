const mongoose = require('mongoose');

const vendorSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  companyName: { type: String, required: true },
  couponCode: String,
  companyAddress: { type: String, required: true },
  active: { type: Boolean, default: false },
  referralLink: { type: String, unique: true },
  referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  wallet: { type: Number, default: 0 },
  referralLinkActive: { type: Boolean, default: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastLogin: { type: Date },
  role: { type: String, enum: ['user', 'admin', 'vendor'], default: 'vendor' },
}, { timestamps: true });

module.exports = mongoose.model('Vendor', vendorSchema);
