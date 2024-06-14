const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  username: String,
  password: String,
  // Other admin-specific fields
});

const Admin = mongoose.model('Admin', adminSchema);
module.exports = Admin;
