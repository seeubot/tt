// server.js - Single File Backend Server
require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mongoose = require('mongoose');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const compression = require('compression');

const app = express();

// ============ Security Middleware ============
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ============ Rate Limiting ============
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const chatCreationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many chat creations, please try again later.' }
});

app.use('/api/', globalLimiter);
app.use('/api/chat/create', chatCreationLimiter);

// ============ Database Connection ============
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/secretchat';

mongoose.connect(MONGODB_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => console.log('MongoDB connected'))
.catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ============ MongoDB Models ============
const chatSchema = new mongoose.Schema({
  chatId: { type: String, required: true, unique: true, index: true },
  shareCode: { type: String, required: true, unique: true, index: true },
  participants: [{
    userId: { type: String, required: true },
    deviceId: { type: String, required: true },
    publicKey: { type: String },
    joinedAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    isOnline: { type: Boolean, default: false },
    isTyping: { type: Boolean, default: false }
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

// TTL index for auto-deletion
messageSchema.index({ selfDestructAt: 1 }, { expireAfterSeconds: 0 });
chatSchema.index({ lastActivity: 1 }, { expireAfterSeconds: 24 * 60 * 60 });

const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);

// ============ Helper Functions ============
const generateId = (length = 16) => crypto.randomBytes(length).toString('hex');
const generateShareCode = () => crypto.randomBytes(3).toString('hex').toUpperCase().substring(0, 6);
const generateUserId = () => 'U' + crypto.randomBytes(6).toString('hex');
const generateEncryptionKey = () => crypto.randomBytes(32).toString('base64');

// ============ WebSocket Setup ============
const server = http.createServer(app);
const wss = new WebSocket.Server({ 
  server,
  maxPayload: 1024 * 1024,
});

const activeConnections = new Map();
const userSessions = new Map();

wss.on('connection', async (ws, req) => {
  ws.isAlive = true;
  ws.id = generateId();
  
  let userId = null;
  let chatId = null;

  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    chatId = url.searchParams.get('chatId');
    userId = url.searchParams.get('userId');

    if (!chatId || !userId) {
      ws.close(4000, 'Missing parameters');
      return;
    }

    const chat = await Chat.findOne({ 
      chatId, 
      status: 'active',
      'participants.userId': userId 
    });

    if (!chat) {
      ws.close(4003, 'Chat not found');
      return;
    }

    ws.userId = userId;
    ws.chatId = chatId;

    if (!activeConnections.has(chatId)) {
      activeConnections.set(chatId, new Set());
    }
    activeConnections.get(chatId).add(ws);
    userSessions.set(userId, ws);

    await Chat.updateOne(
      { chatId, 'participants.userId': userId },
      { 
        $set: { 
          'participants.$.isOnline': true,
          'participants.$.lastSeen': new Date(),
          lastActivity: new Date()
        } 
      }
    );

    broadcastToChat(chatId, {
      type: 'user_status',
      userId,
      status: 'online',
      timestamp: new Date().toISOString()
    }, ws);

    ws.send(JSON.stringify({
      type: 'connection_established',
      chatId,
      userId,
      timestamp: new Date().toISOString()
    }));

    console.log(`User ${userId} connected to chat ${chatId}`);

  } catch (error) {
    console.error('Connection error:', error);
    ws.close(4002, 'Connection failed');
    return;
  }

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());
      
      switch (message.type) {
        case 'message':
          await handleChatMessage(chatId, userId, message, ws);
          break;
          
        case 'typing':
          broadcastToChat(chatId, {
            type: 'typing_status',
            userId,
            isTyping: message.isTyping,
            timestamp: new Date().toISOString()
          }, ws);
          break;
          
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
          
        default:
          console.warn(`Unknown message type: ${message.type}`);
      }
    } catch (error) {
      console.error('Message error:', error);
      ws.send(JSON.stringify({ type: 'error', error: 'Message processing failed' }));
    }
  });

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('close', async () => {
    console.log(`User ${userId} disconnected`);
    
    const connections = activeConnections.get(chatId);
    if (connections) {
      connections.delete(ws);
      if (connections.size === 0) {
        activeConnections.delete(chatId);
      }
    }
    userSessions.delete(userId);

    try {
      await Chat.updateOne(
        { chatId, 'participants.userId': userId },
        { 
          $set: { 
            'participants.$.isOnline': false,
            'participants.$.lastSeen': new Date(),
            lastActivity: new Date()
          } 
        }
      );

      broadcastToChat(chatId, {
        type: 'user_status',
        userId,
        status: 'offline',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Disconnect error:', error);
    }
  });
});

// Heartbeat
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(interval));

async function handleChatMessage(chatId, userId, message, senderWs) {
  const { content, iv, messageType = 'text' } = message;
  
  if (!content) return;

  const selfDestructAt = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes

  const newMessage = await Message.create({
    chatId,
    senderId: userId,
    messageType,
    content,
    iv,
    selfDestructAt
  });

  await Chat.updateOne(
    { chatId },
    { 
      $inc: { messageCount: 1 },
      $set: { lastActivity: new Date() }
    }
  );

  senderWs.send(JSON.stringify({
    type: 'message_sent',
    messageId: newMessage._id,
    timestamp: newMessage.createdAt
  }));

  broadcastToChat(chatId, {
    type: 'new_message',
    messageId: newMessage._id,
    content,
    iv,
    messageType,
    senderId: userId,
    selfDestructAt: selfDestructAt.toISOString(),
    timestamp: newMessage.createdAt.toISOString()
  }, senderWs);
}

function broadcastToChat(chatId, data, excludeWs = null) {
  const connections = activeConnections.get(chatId);
  if (!connections) return;

  const messageStr = JSON.stringify(data);
  connections.forEach((client) => {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      client.send(messageStr);
    }
  });
}

// ============ API Routes ============

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    activeConnections: wss.clients.size
  });
});

// Create new chat
app.post('/api/chat/create', async (req, res) => {
  try {
    const { deviceId, publicKey } = req.body;

    if (!deviceId) {
      return res.status(400).json({ error: 'Device ID is required' });
    }

    // Check active chats limit
    const activeChats = await Chat.countDocuments({
      'participants.deviceId': deviceId,
      status: 'active'
    });

    if (activeChats >= 5) {
      return res.status(429).json({ error: 'Maximum active chats reached. Delete some old chats.' });
    }

    const chatId = generateId(12);
    const shareCode = generateShareCode();
    const userId = generateUserId();
    const encryptionKey = generateEncryptionKey();

    await Chat.create({
      chatId,
      shareCode,
      participants: [{
        userId,
        deviceId,
        publicKey: publicKey || '',
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
      message: 'Chat created successfully. Share the code with your partner.'
    });

  } catch (error) {
    console.error('Chat creation error:', error);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

// Join existing chat
app.post('/api/chat/join', async (req, res) => {
  try {
    const { shareCode, deviceId, publicKey } = req.body;

    if (!shareCode || !deviceId) {
      return res.status(400).json({ error: 'Share code and device ID are required' });
    }

    const chat = await Chat.findOne({ 
      shareCode: shareCode.toUpperCase(),
      status: 'active'
    });

    if (!chat) {
      return res.status(404).json({ error: 'Chat not found or expired. Please check the code.' });
    }

    if (chat.participants.length >= 2) {
      return res.status(400).json({ error: 'Chat is already full' });
    }

    // Check if device already in chat
    if (chat.participants.find(p => p.deviceId === deviceId)) {
      return res.status(400).json({ error: 'This device is already in the chat' });
    }

    const userId = generateUserId();

    chat.participants.push({
      userId,
      deviceId,
      publicKey: publicKey || '',
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
      message: 'Successfully joined the chat'
    });

  } catch (error) {
    console.error('Chat join error:', error);
    res.status(500).json({ error: 'Failed to join chat' });
  }
});

// Verify chat exists
app.get('/api/chat/verify/:shareCode', async (req, res) => {
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

// Get chat info
app.get('/api/chat/:chatId', async (req, res) => {
  try {
    const { userId } = req.query;
    
    const chat = await Chat.findOne({ 
      chatId: req.params.chatId,
      'participants.userId': userId,
      status: 'active'
    });

    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    const otherParticipant = chat.participants.find(p => p.userId !== userId);

    res.json({
      chatId: chat.chatId,
      shareCode: chat.shareCode,
      participantsCount: chat.participants.length,
      createdAt: chat.createdAt,
      lastActivity: chat.lastActivity,
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

// Delete chat
app.delete('/api/chat/:chatId', async (req, res) => {
  try {
    const { userId } = req.body;

    const chat = await Chat.findOne({ 
      chatId: req.params.chatId,
      'participants.userId': userId
    });

    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    chat.status = 'deleted';
    await chat.save();

    // Delete all messages
    await Message.deleteMany({ chatId: req.params.chatId });

    res.json({ success: true, message: 'Chat deleted successfully' });

  } catch (error) {
    res.status(500).json({ error: 'Failed to delete chat' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============ Start Server ============
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API URL: http://localhost:${PORT}`);
  console.log(`WebSocket URL: ws://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  wss.clients.forEach((client) => client.close());
  server.close();
  await mongoose.connection.close();
  process.exit(0);
});
