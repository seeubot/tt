require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- MongoDB ----------
let dbReady = false;

if (!process.env.MONGO_URI) {
  console.error('FATAL: MONGO_URI is not set in environment variables.');
} else {
  mongoose.connect(process.env.MONGO_URI)
    .then(() => {
      dbReady = true;
      console.log('MongoDB connected');
    })
    .catch(err => {
      console.error('MongoDB connection error:', err.message);
    });
}

mongoose.connection.on('connected', () => { dbReady = true; });
mongoose.connection.on('disconnected', () => { dbReady = false; });
mongoose.connection.on('error', (err) => {
  console.error('MongoDB runtime error:', err.message);
  dbReady = false;
});

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
let mailReady = false;
let lastMailError = null;

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = process.env.RESEND_FROM || 'onboarding@resend.dev';

if (!RESEND_API_KEY) {
  console.error('WARNING: RESEND_API_KEY is not set. Emails will not be sent.');
  lastMailError = 'RESEND_API_KEY not set';
} else {
  mailReady = true;
  console.log('Resend email API configured');
}

// Send email via Resend HTTP API (works over HTTPS, avoids SMTP port blocks)
async function sendOtpEmail(toEmail, otp) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to: [toEmail],
      subject: 'Your OTP Code',
      html: `<p>Your OTP code is <b>${otp}</b>. It is valid for 5 minutes.</p>`
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Resend API error (${response.status}): ${errBody}`);
  }

  return response.json();
}

// ---------- Helpers ----------
const hashOtp = (otp) => crypto.createHash('sha256').update(otp).digest('hex');

const isValidIndianPhone = (phone) => /^[6-9]\d{9}$/.test(phone);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// Middleware: block API requests if DB isn't ready
function requireDb(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database not connected. Please try again shortly.' });
  }
  next();
}

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

// ---------- Health check ----------
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    mail: mailReady ? 'ready' : 'not_ready',
    mailError: lastMailError
  });
});

// ---------- Routes ----------

// Step 1: Check phone -> tell frontend whether email is needed
app.post('/api/check-phone', requireDb, async (req, res) => {
  try {
    const { phone } = req.body || {};

    if (!phone || !isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Enter a valid 10-digit Indian phone number.' });
    }

    const user = await User.findOne({ phone });

    if (user) {
      return res.json({ emailRequired: false, message: 'Phone number recognized.' });
    } else {
      return res.json({ emailRequired: true, message: 'New phone number. Please provide your email.' });
    }
  } catch (err) {
    console.error('check-phone error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// Step 2: Send OTP to email (existing or newly provided)
app.post('/api/send-otp', otpRequestLimiter, requireDb, async (req, res) => {
  try {
    const { phone, email } = req.body || {};

    if (!phone || !isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Enter a valid 10-digit Indian phone number.' });
    }

    if (!RESEND_API_KEY) {
      return res.status(503).json({ error: 'Email service is not configured on the server.' });
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

    await sendOtpEmail(targetEmail, otp);

    // Mask email for privacy in response
    const maskedEmail = targetEmail.replace(/^(.{2}).+(@.+)$/, '$1***$2');

    res.json({ success: true, message: `OTP sent to ${maskedEmail}` });
  } catch (err) {
    console.error('send-otp error:', err);
    res.status(500).json({ error: 'Failed to send OTP: ' + err.message });
  }
});

// Step 3: Verify OTP and create user if new
app.post('/api/verify-otp', otpVerifyLimiter, requireDb, async (req, res) => {
  try {
    const { phone, otp } = req.body || {};

    if (!phone || !isValidIndianPhone(phone) || !otp) {
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
    console.error('verify-otp error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// Catch-all error handler for unexpected issues
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Unexpected server error.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
