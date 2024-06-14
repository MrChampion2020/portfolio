const mongoose = require('mongoose');

const CouponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  value: { type: Number, required: true },
  currency: { type: String, required: true },
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  status: { type: String, enum: ['active', 'used'], default: 'active' },
   userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true }
  
});

module.exports = mongoose.model('Coupon', CouponSchema);



