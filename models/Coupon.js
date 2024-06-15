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


