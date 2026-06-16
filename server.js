require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- MongoDB ----------
if (!process.env.MONGO_URI) {
  console.error('FATAL: MONGO_URI is not set in environment variables.');
  process.exit(1);
}

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
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
  createdAt: { type: Date, default: Date.now, expires: 600 }
});

const User = mongoose.model('User', userSchema);
const Otp = mongoose.model('Otp', otpSchema);

// ---------- Brevo Email Configuration ----------
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL;
const BREVO_FROM_NAME = process.env.BREVO_FROM_NAME || 'OTP Login App';

let mailReady = false;
if (!BREVO_API_KEY || !BREVO_FROM_EMAIL) {
  console.error('WARNING: BREVO_API_KEY or BREVO_FROM_EMAIL is not set. Emails will not be sent.');
} else {
  mailReady = true;
  console.log('Brevo email API configured');
}

// Send OTP email via Brevo
async function sendOtpEmail(toEmail, otp) {
  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': BREVO_API_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({
      sender: { 
        name: BREVO_FROM_NAME, 
        email: BREVO_FROM_EMAIL 
      },
      to: [{ 
        email: toEmail 
      }],
      subject: 'OTP for MORO',
      htmlContent: `
      <!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { 
      font-family: 'Helvetica Neue', Arial, sans-serif; 
      line-height: 1.6; 
      color: #2D3142; 
      background-color: #F7F9FB;
      margin: 0;
      padding: 0;
    }
    .container { 
      max-width: 500px; 
      margin: 40px auto; 
      background: #FFFFFF;
      border-radius: 16px; 
      overflow: hidden;
      box-shadow: 0 4px 15px rgba(0,0,0,0.05);
    }
    .header { 
      background: #1A1C23; 
      padding: 30px 20px; 
      text-align: center; 
    }
    .logo {
      font-size: 28px;
      font-weight: 900;
      color: #FF6B35;
      letter-spacing: 2px;
      margin: 0;
    }
    .logo span {
      color: #FFFFFF;
    }
    .content { 
      padding: 40px 30px; 
      text-align: center;
    }
    h2 {
      font-size: 22px;
      color: #1A1C23;
      margin-top: 0;
      margin-bottom: 10px;
    }
    p {
      color: #6C757D;
      font-size: 15px;
      margin: 0 0 20px 0;
    }
    .otp-container {
      background: #FFF8F5;
      border: 2px dashed #FF6B35;
      border-radius: 12px;
      padding: 20px;
      margin: 30px 0;
    }
    .otp-code { 
      font-size: 36px; 
      font-weight: 800; 
      color: #FF6B35; 
      letter-spacing: 6px; 
      line-height: 1;
    }
    .expiry-text {
      font-size: 13px;
      color: #FF6B35;
      font-weight: 600;
      margin-top: 8px;
      display: block;
    }
    .security-note {
      font-size: 13px;
      color: #ADB5BD;
      border-top: 1px solid #EEF1F6;
      padding-top: 20px;
      margin-top: 30px;
    }
    .footer { 
      text-align: center; 
      color: #ADB5BD; 
      font-size: 12px; 
      padding: 0 20px 30px 20px;
    }
    .footer a {
      color: #FF6B35;
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header with MORO Branding -->
    <div class="header">
      <h1 class="logo">MO<span>RO</span></h1>
    </div>
    
    <!-- Main Content -->
    <div class="content">
      <h2>Hungry? Let's get you verified!</h2>
      <p>Use the verification code below to complete your request on the MORO app.</p>
      
      <!-- OTP Box -->
      <div class="otp-container">
        <div class="otp-code">${otp}</div>
        <span class="expiry-text">⏱ Valid for 5 minutes only</span>
      </div>
      
      <p class="security-note">
        If you didn't request this code, you can safely ignore this email. Someone might have typed your info by mistake.
      </p>
    </div>
    
    <!-- Footer -->
    <div class="footer">
      <p>Sent with 🧡 from MORO HQ</p>
      <p>This is an automated message, please do not reply.</p>
    </div>
  </div>
</body>
</html>
      `
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Brevo API error (${response.status}): ${errBody}`);
  }

  return response.json();
}

// ---------- Helpers ----------
const hashOtp = (otp) => crypto.createHash('sha256').update(otp).digest('hex');
const isValidIndianPhone = (phone) => /^[6-9]\d{9}$/.test(phone);
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

function requireDb(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database not connected. Please try again shortly.' });
  }
  next();
}

// ---------- Rate limiters ----------
const otpRequestLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { error: 'Too many OTP requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const otpVerifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Too many verification attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- Health check ----------
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    mail: mailReady ? 'ready' : 'not_ready'
  });
});

// ---------- Routes ----------
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

app.post('/api/send-otp', otpRequestLimiter, requireDb, async (req, res) => {
  try {
    const { phone, email } = req.body || {};

    if (!phone || !isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Enter a valid 10-digit Indian phone number.' });
    }

    if (!mailReady) {
      return res.status(503).json({ error: 'Email service is not configured on the server.' });
    }

    let user = await User.findOne({ phone });
    let targetEmail;

    if (user) {
      targetEmail = user.email;
    } else {
      if (!email || !isValidEmail(email)) {
        return res.status(400).json({ error: 'A valid email is required for a new phone number.' });
      }
      targetEmail = email.toLowerCase().trim();
    }

    const otp = generateOtp();
    const otpHash = hashOtp(otp);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await Otp.deleteMany({ phone });
    await Otp.create({ phone, email: targetEmail, otpHash, expiresAt });
    
    // Send email via Brevo
    await sendOtpEmail(targetEmail, otp);

    const maskedEmail = targetEmail.replace(/^(.{2}).+(@.+)$/, '$1***$2');
    res.json({ success: true, message: `OTP sent to ${maskedEmail}` });
  } catch (err) {
    console.error('send-otp error:', err);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

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

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Unexpected server error.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
