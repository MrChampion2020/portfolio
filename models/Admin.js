const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  username: { type: String, default: 'admin' },
  password: { type: String, default: 'Admin' }
  // Other admin-specific fields
});

const Admin = mongoose.model('Admin', adminSchema);
module.exports = Admin;
