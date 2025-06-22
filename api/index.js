import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';

const app = express();
app.use(cors());
app.use(express.json());

// Подключение к MongoDB (используйте MongoDB Atlas для production)
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/soft-planner';
mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Модели данных
const User = mongoose.model('User', new mongoose.Schema({
  userId: { type: String, unique: true },
  name: String,
  email: { type: String, unique: true },
  password: String,
  language: { type: String, default: 'ru' },
  theme: { type: String, default: 'dark' },
  workspaces: [String],
  notifications: [{
    id: String,
    type: String,
    title: String,
    message: String,
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false },
    workspaceId: String,
    taskId: String
  }]
}));

// Генерация 6-значного ID
function generateUserId() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Middleware аутентификации
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'secret123', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// API Endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = generateUserId();

    const user = new User({ userId, name, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ email, userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });
    res.status(201).send({ token, userId });
  } catch (err) {
    res.status(400).send({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ email, userId: user.userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });
    res.send({ token, userId: user.userId, name: user.name });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

// Экспорт для Vercel
export default app;
