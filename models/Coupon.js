/*const mongoose = require('mongoose');

const CouponSchema = new mongoose.Schema({

 code: { type: String, required: true, unique: true },
 value: { type: Number, required: true },
 currency: { type: String, required: true },
 userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  isActive: { type: Boolean, default: true },
  isUsed: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'used'], default: 'active' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true,  timestamps: true }

});
module.exports = mongoose.model('Coupon', CouponSchema);
*/

const mongoose = require("mongoose");

const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  value: { type: Number, required: true },
  currency: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isActive: { type: Boolean, default: true },
  isUsed: { type: Boolean, default: false },
});

module.exports = mongoose.model("Coupon", couponSchema);
