const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

const auth = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    res.json(user.wallet);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

router.post('/withdraw', auth, async (req, res) => {
  const { amount } = req.body;

  try {
    const user = await User.findById(req.userId);
    if (user.wallet < amount) return res.status(400).json({ msg: 'Insufficient funds' });

    user.wallet -= amount;
    await user.save();

    res.json({ msg: 'Withdrawal request submitted', wallet: user.wallet });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

module.exports = router;
