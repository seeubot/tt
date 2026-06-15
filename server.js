require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- MongoDB ----------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  phone: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  phone: { type: String, required: true, index: true },
  email: { type: String, required: true },
  otpHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now, expires: 600 } // auto-delete after 10 min
});

const User = mongoose.model('User', userSchema);
const Otp = mongoose.model('Otp', otpSchema);

// ---------- Mail transporter ----------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ---------- Helpers ----------
const hashOtp = (otp) => crypto.createHash('sha256').update(otp).digest('hex');

const isValidIndianPhone = (phone) => /^[6-9]\d{9}$/.test(phone);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// ---------- Rate limiters ----------
const otpRequestLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  message: { error: 'Too many OTP requests. Please try again later.' }
});

const otpVerifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Too many verification attempts. Please try again later.' }
});

// ---------- Routes ----------

// Step 1: Check phone -> tell frontend whether email is needed
app.post('/api/check-phone', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Enter a valid 10-digit Indian phone number.' });
    }

    const user = await User.findOne({ phone });

    if (user) {
      return res.json({ emailRequired: false, message: 'Phone number recognized.' });
    } else {
      return res.json({ emailRequired: true, message: 'New phone number. Please provide your email.' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Step 2: Send OTP to email (existing or newly provided)
app.post('/api/send-otp', otpRequestLimiter, async (req, res) => {
  try {
    const { phone, email } = req.body;

    if (!isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Enter a valid 10-digit Indian phone number.' });
    }

    let user = await User.findOne({ phone });
    let targetEmail;

    if (user) {
      // Existing user - use stored email, ignore any email passed in
      targetEmail = user.email;
    } else {
      // New user - email is required
      if (!email || !isValidEmail(email)) {
        return res.status(400).json({ error: 'A valid email is required for a new phone number.' });
      }
      targetEmail = email.toLowerCase().trim();
    }

    const otp = generateOtp();
    const otpHash = hashOtp(otp);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Remove any previous OTPs for this phone
    await Otp.deleteMany({ phone });

    await Otp.create({ phone, email: targetEmail, otpHash, expiresAt });

    await transporter.sendMail({
      from: `"OTP Login" <${process.env.SMTP_USER}>`,
      to: targetEmail,
      subject: 'Your OTP Code',
      html: `<p>Your OTP code is <b>${otp}</b>. It is valid for 5 minutes.</p>`
    });

    // Mask email for privacy in response
    const maskedEmail = targetEmail.replace(/^(.{2}).+(@.+)$/, '$1***$2');

    res.json({ success: true, message: `OTP sent to ${maskedEmail}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// Step 3: Verify OTP and create user if new
app.post('/api/verify-otp', otpVerifyLimiter, async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!isValidIndianPhone(phone) || !otp) {
      return res.status(400).json({ error: 'Invalid request.' });
    }

    const record = await Otp.findOne({ phone });

    if (!record) {
      return res.status(400).json({ error: 'OTP expired or not found. Please request a new one.' });
    }

    if (record.expiresAt < new Date()) {
      await Otp.deleteOne({ _id: record._id });
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    }

    if (record.attempts >= 5) {
      await Otp.deleteOne({ _id: record._id });
      return res.status(400).json({ error: 'Too many incorrect attempts. Please request a new OTP.' });
    }

    if (hashOtp(otp) !== record.otpHash) {
      record.attempts += 1;
      await record.save();
      return res.status(400).json({ error: 'Incorrect OTP.' });
    }

    // OTP correct - create user if doesn't exist
    let user = await User.findOne({ phone });
    if (!user) {
      user = await User.create({ phone, email: record.email });
    }

    await Otp.deleteOne({ _id: record._id });

    res.json({
      success: true,
      message: 'Login successful.',
      user: { phone: user.phone, email: user.email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
