const mongoose = require('mongoose');

const vendorSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  companyName: { type: String, required: true },
  companyAddress: { type: String, required: true },
  active: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('Vendor', vendorSchema);
