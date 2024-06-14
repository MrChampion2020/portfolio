const mongoose = require('mongoose');

const CouponSchema = new mongoose.Schema({
<<<<<<< HEAD
 code: { type: String, required: true, unique: true },
 value: { type: Number, required: true },
 currency: { type: String, required: true },
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  status: { type: String, enum: ['active', 'used'], default: 'active' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
=======
  code: { type: String, required: true, unique: true },
  value: { type: Number, required: true },
  currency: { type: String, required: true },
  vendorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vendor' },
  status: { type: String, enum: ['active', 'used'], default: 'active' },
   userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
>>>>>>> 14e0641296392591aa91815db0f2a139321e6645
}, { timestamps: true }
  
);

module.exports = mongoose.model('Coupon', CouponSchema);

<<<<<<< HEAD
=======


>>>>>>> 14e0641296392591aa91815db0f2a139321e6645
