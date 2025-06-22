require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Настройка CORS для работы с фронтендом
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://soft-planner-mija.vercel.app',
  credentials: true
}));
app.use(express.json());

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/soft-planner')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Модель пользователя
const UserSchema = new mongoose.Schema({
  userId: { type: String, unique: true },
  name: String,
  email: { type: String, unique: true },
  password: String,
  tasks: [{
    title: String,
    description: String,
    dueDate: Date,
    priority: String,
    completed: Boolean
  }]
});

const User = mongoose.model('User', UserSchema);

// Генерация 6-значного ID
const generateUserId = () => Math.floor(100000 + Math.random() * 900000).toString();

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Валидация
    if (!name || !email || !password) {
      return res.status(400).json({ 
        error: 'All fields are required',
        fields: { name: !name, email: !email, password: !password }
      });
    }

    if (await User.findOne({ email })) {
      return res.status(400).json({ 
        error: 'Email already exists',
        field: 'email'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = generateUserId();

    const user = new User({
      userId,
      name,
      email,
      password: hashedPassword,
      tasks: []
    });

    await user.save();

    const token = jwt.sign({ userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });

    res.status(201).json({
      success: true,
      token,
      userId,
      name
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Registration failed',
      details: error.message 
    });
  }
});

// Авторизация
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Валидация
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required',
        fields: { email: !email, password: !password }
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        field: 'email'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        field: 'password'
      });
    }

    const token = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      userId: user.userId,
      name: user.name
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Login failed',
      details: error.message 
    });
  }
});

// Middleware для проверки авторизации
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Получение задач (только для авторизованных)
app.get('/api/tasks', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      tasks: user.tasks
    });

  } catch (error) {
    console.error('Tasks error:', error);
    res.status(500).json({ 
      error: 'Failed to get tasks',
      details: error.message 
    });
  }
});

// Проверка авторизации
app.get('/api/check-auth', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      userId: user.userId,
      name: user.name
    });
  } catch (error) {
    console.error('Check auth error:', error);
    res.status(500).json({ 
      error: 'Auth check failed',
      details: error.message 
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
