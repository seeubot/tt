// server.js - Final Production Version
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const compression = require('compression');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Security
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(compression());

// ============ MongoDB Connection ============
const MONGODB_URI = process.env.MONGO_URI;

if (!MONGODB_URI) {
  console.error('FATAL: MONGO_URI is not set');
  process.exit(1);
}

console.log('Connecting to MongoDB...');
console.log('URI:', MONGODB_URI.replace(/\/\/.*@/, '//<credentials>@')); // Hide credentials in logs

mongoose.connect(MONGODB_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  retryWrites: true,
  w: 'majority',
})
.then(() => {
  console.log('MongoDB connected successfully');
})
.catch(err => {
  console.error('MongoDB connection error:', err.message);
  // Don't exit - let the health check report the status
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB error:', err.message);
});

// ============ Models ============
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

const chatSchema = new mongoose.Schema({
  chatId: { type: String, required: true, unique: true, index: true },
  shareCode: { type: String, required: true, unique: true, index: true },
  phone: { type: String, required: true, index: true },
  participants: [{
    userId: { type: String, required: true },
    phone: { type: String, required: true },
    deviceId: { type: String },
    joinedAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    isOnline: { type: Boolean, default: false }
  }],
  encryptionKey: { type: String },
  messageCount: { type: Number, default: 0 },
  status: { type: String, enum: ['active', 'deleted'], default: 'active' },
  lastActivity: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  chatId: { type: String, required: true, index: true },
  senderId: { type: String, required: true },
  messageType: { type: String, enum: ['text', 'audio', 'system'], default: 'text' },
  content: { type: String, required: true },
  iv: { type: String },
  selfDestructAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

messageSchema.index({ selfDestructAt: 1 }, { expireAfterSeconds: 0 });
chatSchema.index({ lastActivity: 1 }, { expireAfterSeconds: 86400 });

const User = mongoose.model('User', userSchema);
const Otp = mongoose.model('Otp', otpSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);

// ============ Helpers ============
const hashOtp = (otp) => crypto.createHash('sha256').update(otp).digest('hex');
const isValidIndianPhone = (phone) => /^[6-9]\d{9}$/.test(phone);
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();
const generateId = (len = 16) => crypto.randomBytes(len).toString('hex');
const generateShareCode = () => crypto.randomBytes(3).toString('hex').toUpperCase().substring(0, 6);
const generateUserId = () => 'U' + crypto.randomBytes(6).toString('hex');
const generateEncryptionKey = () => crypto.randomBytes(32).toString('base64');

function requireDb(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database not connected' });
  }
  next();
}

// ============ Brevo Email ============
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL;
const BREVO_FROM_NAME = process.env.BREVO_FROM_NAME || 'OTP Login App';
let mailReady = !!(BREVO_API_KEY && BREVO_FROM_EMAIL);

if (mailReady) {
  console.log('Brevo email service configured');
} else {
  console.warn('Brevo email not configured');
}

async function sendOtpEmail(toEmail, otp) {
  if (!mailReady) throw new Error('Email service not configured');

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': BREVO_API_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: BREVO_FROM_NAME, email: BREVO_FROM_EMAIL },
      to: [{ email: toEmail }],
      subject: 'Your Verification Code - OTP Login',
      htmlContent: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 20px; }
            .logo { font-size: 24px; font-weight: bold; color: #1a1a2e; letter-spacing: 2px; }
            .logo span { color: #ff6b35; }
            .code { font-size: 36px; font-weight: bold; color: #ff6b35; letter-spacing: 8px; text-align: center; padding: 20px; background: #fff8f5; border-radius: 8px; border: 2px dashed #ff6b35; margin: 20px 0; }
            .info { color: #666; font-size: 13px; text-align: center; }
            .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #999; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <div class="logo">MO<span>RO</span></div>
            </div>
            <p style="text-align: center; color: #333;">Your verification code:</p>
            <div class="code">${otp}</div>
            <p class="info">This code is valid for 5 minutes only</p>
            <div class="footer">
              <p>If you didn't request this code, please ignore this email.</p>
              <p>Sent with ❤️ from MORO</p>
            </div>
          </div>
        </body>
        </html>
      `
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    console.error('Brevo API error:', response.status, errBody);
    throw new Error(`Email sending failed: ${response.status}`);
  }

  console.log('OTP email sent to:', toEmail);
  return response.json();
}

// ============ Rate Limiters ============
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
  message: { error: 'Too many verification attempts.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const chatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many requests.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============ Routes ============

// Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    mail: mailReady ? 'ready' : 'not_ready',
    uptime: process.uptime()
  });
});

// Home
app.get('/', (req, res) => {
  res.json({
    app: 'Phone OTP Auth + Secret Chat API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      checkPhone: 'POST /api/check-phone',
      sendOtp: 'POST /api/send-otp',
      verifyOtp: 'POST /api/verify-otp',
      createChat: 'POST /api/chat/create',
      joinChat: 'POST /api/chat/join',
      verifyChat: 'GET /api/chat/verify/:shareCode',
      getChat: 'GET /api/chat/:chatId',
      deleteChat: 'DELETE /api/chat/:chatId',
      sendMessage: 'POST /api/messages/send',
      getMessages: 'GET /api/messages/:chatId'
    }
  });
});

// ============ OTP Auth Routes ============
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
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/send-otp', otpRequestLimiter, requireDb, async (req, res) => {
  try {
    const { phone, email } = req.body || {};
    if (!phone || !isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Enter a valid phone number.' });
    }
    if (!mailReady) {
      return res.status(503).json({ error: 'Email service not configured.' });
    }

    let user = await User.findOne({ phone });
    let targetEmail;

    if (user) {
      targetEmail = user.email;
    } else {
      if (!email || !isValidEmail(email)) {
        return res.status(400).json({ error: 'Valid email required for new phone number.' });
      }
      targetEmail = email.toLowerCase().trim();
    }

    const otp = generateOtp();
    const otpHash = hashOtp(otp);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await Otp.deleteMany({ phone });
    await Otp.create({ phone, email: targetEmail, otpHash, expiresAt });
    
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
      return res.status(400).json({ error: 'OTP expired or not found. Request a new one.' });
    }
    if (record.expiresAt < new Date()) {
      await Otp.deleteOne({ _id: record._id });
      return res.status(400).json({ error: 'OTP expired. Request a new one.' });
    }
    if (record.attempts >= 5) {
      await Otp.deleteOne({ _id: record._id });
      return res.status(400).json({ error: 'Too many incorrect attempts. Request a new OTP.' });
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
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ Chat Routes ============
app.post('/api/chat/create', chatLimiter, requireDb, async (req, res) => {
  try {
    const { phone, deviceId } = req.body;
    if (!phone || !isValidIndianPhone(phone)) {
      return res.status(400).json({ error: 'Valid phone number required' });
    }

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({ error: 'Please verify your phone number first' });
    }

    const activeChats = await Chat.countDocuments({
      'participants.phone': phone,
      status: 'active'
    });
    if (activeChats >= 5) {
      return res.status(429).json({ error: 'Maximum 5 active chats allowed' });
    }

    const chatId = generateId(12);
    const shareCode = generateShareCode();
    const userId = generateUserId();
    const encryptionKey = generateEncryptionKey();

    await Chat.create({
      chatId,
      shareCode,
      phone,
      participants: [{
        userId,
        phone,
        deviceId: deviceId || '',
        isOnline: true,
        joinedAt: new Date()
      }],
      encryptionKey,
      status: 'active',
      lastActivity: new Date()
    });

    res.status(201).json({
      success: true,
      chatId,
      shareCode,
      userId,
      encryptionKey,
      message: `Share code: ${shareCode}`
    });
  } catch (error) {
    console.error('Chat creation error:', error);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

app.post('/api/chat/join', chatLimiter, requireDb, async (req, res) => {
  try {
    const { shareCode, phone, deviceId } = req.body;
    if (!shareCode || !phone) {
      return res.status(400).json({ error: 'Share code and phone required' });
    }

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({ error: 'Please verify your phone number first' });
    }

    const chat = await Chat.findOne({ 
      shareCode: shareCode.toUpperCase(),
      status: 'active'
    });
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found or expired' });
    }
    if (chat.participants.length >= 2) {
      return res.status(400).json({ error: 'Chat is full' });
    }
    if (chat.participants.find(p => p.phone === phone)) {
      return res.status(400).json({ error: 'Already in this chat' });
    }

    const userId = generateUserId();
    chat.participants.push({
      userId,
      phone,
      deviceId: deviceId || '',
      isOnline: true,
      joinedAt: new Date()
    });
    chat.lastActivity = new Date();
    await chat.save();

    res.json({
      success: true,
      chatId: chat.chatId,
      userId,
      encryptionKey: chat.encryptionKey,
      message: 'Joined successfully'
    });
  } catch (error) {
    console.error('Chat join error:', error);
    res.status(500).json({ error: 'Failed to join chat' });
  }
});

app.get('/api/chat/verify/:shareCode', requireDb, async (req, res) => {
  try {
    const chat = await Chat.findOne({ 
      shareCode: req.params.shareCode.toUpperCase(),
      status: 'active',
      $expr: { $lt: [{ $size: '$participants' }, 2] }
    });
    res.json({ 
      exists: !!chat,
      participantsCount: chat ? chat.participants.length : 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.get('/api/chat/:chatId', requireDb, async (req, res) => {
  try {
    const { userId } = req.query;
    const chat = await Chat.findOne({ 
      chatId: req.params.chatId,
      'participants.userId': userId,
      status: 'active'
    });
    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    const otherParticipant = chat.participants.find(p => p.userId !== userId);
    res.json({
      chatId: chat.chatId,
      shareCode: chat.shareCode,
      participantsCount: chat.participants.length,
      otherParticipant: otherParticipant ? {
        userId: otherParticipant.userId,
        isOnline: otherParticipant.isOnline,
        lastSeen: otherParticipant.lastSeen
      } : null
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get chat info' });
  }
});

app.delete('/api/chat/:chatId', requireDb, async (req, res) => {
  try {
    const { userId } = req.body;
    const chat = await Chat.findOne({ 
      chatId: req.params.chatId,
      'participants.userId': userId
    });
    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    chat.status = 'deleted';
    await chat.save();
    await Message.deleteMany({ chatId: req.params.chatId });
    res.json({ success: true, message: 'Chat deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete chat' });
  }
});

// ============ Message Routes ============
app.post('/api/messages/send', requireDb, async (req, res) => {
  try {
    const { chatId, userId, content, messageType = 'text', iv } = req.body;
    
    if (!chatId || !userId || !content) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const chat = await Chat.findOne({ 
      chatId, 
      status: 'active',
      'participants.userId': userId 
    });
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    const selfDestructAt = new Date(Date.now() + 2 * 60 * 1000);
    
    const message = await Message.create({
      chatId,
      senderId: userId,
      messageType,
      content,
      iv,
      selfDestructAt
    });

    await Chat.updateOne(
      { chatId },
      { $inc: { messageCount: 1 }, $set: { lastActivity: new Date() } }
    );

    res.status(201).json({
      success: true,
      messageId: message._id,
      timestamp: message.createdAt
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/messages/:chatId', requireDb, async (req, res) => {
  try {
    const { userId, after } = req.query;
    const chatId = req.params.chatId;

    const chat = await Chat.findOne({ 
      chatId, 
      status: 'active',
      'participants.userId': userId 
    });
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    let query = { chatId };
    if (after) {
      query.createdAt = { $gt: new Date(after) };
    }

    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(50);

    res.json({
      messages: messages.reverse(),
      lastCheck: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// ============ Error Handlers ============
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============ Start Server ============
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Brevo email: ${mailReady ? 'Configured' : 'Not configured'}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  await mongoose.connection.close();
  process.exit(0);
});
