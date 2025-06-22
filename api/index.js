require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
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
    
    if (await User.findOne({ email })) {
      return res.status(400).json({ error: 'Email already exists' });
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
      token,
      userId,
      name,
      message: 'Registration successful'
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Авторизация
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });

    res.json({
      token,
      userId: user.userId,
      name: user.name
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Получение задач
app.get('/api/tasks', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const { userId } = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const user = await User.findOne({ userId });

    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json(user.tasks);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running on port ${process.env.PORT || 5000}`);
});
