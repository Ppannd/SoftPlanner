require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// Путь к файлу БД (в /tmp для Vercel)
const DB_PATH = path.join('/tmp', 'softplanner.db');
const db = new sqlite3.Database(DB_PATH);

// Инициализация БД
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    userId TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    avatar TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    taskId TEXT PRIMARY KEY,
    userId TEXT,
    title TEXT,
    description TEXT,
    dueDate TEXT,
    priority TEXT CHECK(priority IN ('high', 'medium', 'low')),
    completed INTEGER DEFAULT 0,
    tags TEXT,
    FOREIGN KEY(userId) REFERENCES users(userId)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS workspaces (
    workspaceId TEXT PRIMARY KEY,
    userId TEXT,
    name TEXT,
    FOREIGN KEY(userId) REFERENCES users(userId)
  )`);
});

// Генерация JWT токена
function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });
}

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Проверка существования пользователя
    const userExists = await new Promise((resolve) => {
      db.get("SELECT email FROM users WHERE email = ?", [email], (err, row) => {
        if (err) throw err;
        resolve(!!row);
      });
    });

    if (userExists) {
      return res.status(400).json({ success: false, error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const avatar = name.charAt(0).toUpperCase();

    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO users (userId, name, email, password, avatar) VALUES (?, ?, ?, ?, ?)",
        [userId, name, email, hashedPassword, avatar],
        (err) => err ? reject(err) : resolve()
      );
    });

    const token = generateToken(userId);

    res.json({
      success: true,
      token,
      userId,
      name,
      avatar
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// Авторизация
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await new Promise((resolve) => {
      db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
        if (err) throw err;
        resolve(row);
      });
    });

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const token = generateToken(user.userId);

    res.json({
      success: true,
      token,
      userId: user.userId,
      name: user.name,
      avatar: user.avatar
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

// Middleware для проверки авторизации
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET || 'secret123', (err, decoded) => {
    if (err) return res.status(401).json({ success: false, error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
}

// Получение задач пользователя
app.get('/api/tasks', authenticate, (req, res) => {
  db.all(
    "SELECT * FROM tasks WHERE userId = ? ORDER BY dueDate",
    [req.userId],
    (err, tasks) => {
      if (err) {
        console.error('Tasks error:', err);
        return res.status(500).json({ success: false, error: 'Failed to get tasks' });
      }
      res.json({ success: true, tasks });
    }
  );
});

// Создание задачи
app.post('/api/tasks', authenticate, (req, res) => {
  const { title, description, dueDate, priority, tags } = req.body;
  const taskId = uuidv4();

  db.run(
    "INSERT INTO tasks (taskId, userId, title, description, dueDate, priority, tags) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [taskId, req.userId, title, description, dueDate, priority, JSON.stringify(tags)],
    function(err) {
      if (err) {
        console.error('Create task error:', err);
        return res.status(500).json({ success: false, error: 'Failed to create task' });
      }
      res.json({ success: true, taskId });
    }
  );
});

// Остальные API endpoints (редактирование, удаление задач и т.д.)...

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
