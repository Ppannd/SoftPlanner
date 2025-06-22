require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// Путь к файлу данных
const DATA_FILE = path.join(__dirname, 'data.json');

// Инициализация файла данных
async function initDataFile() {
  try {
    await fs.access(DATA_FILE);
  } catch {
    await fs.writeFile(DATA_FILE, JSON.stringify({
      users: [],
      tasks: [],
      notifications: []
    }));
  }
}

// Чтение данных
async function readData() {
  const data = await fs.readFile(DATA_FILE, 'utf8');
  return JSON.parse(data);
}

// Запись данных
async function writeData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
}

// Генерация JWT токена
function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });
}

// Middleware для проверки авторизации
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Инициализация при старте
initDataFile();

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const data = await readData();

    if (data.users.some(u => u.email === email)) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const avatar = name.charAt(0).toUpperCase();

    data.users.push({
      userId,
      name,
      email,
      password: hashedPassword,
      avatar,
      notificationsEnabled: true
    });

    await writeData(data);

    const token = generateToken(userId);

    res.json({
      token,
      userId,
      name,
      avatar
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Авторизация
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const data = await readData();

    const user = data.users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user.userId);

    res.json({
      token,
      userId: user.userId,
      name: user.name,
      avatar: user.avatar
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Получение задач
app.get('/api/tasks', authenticate, async (req, res) => {
  try {
    const data = await readData();
    const tasks = data.tasks.filter(t => t.userId === req.userId);
    res.json(tasks);
  } catch (error) {
    console.error('Tasks error:', error);
    res.status(500).json({ error: 'Failed to get tasks' });
  }
});

// Создание задачи
app.post('/api/tasks', authenticate, async (req, res) => {
  try {
    const { title, description, dueDate, priority, tags } = req.body;
    const data = await readData();

    const task = {
      taskId: uuidv4(),
      userId: req.userId,
      title,
      description,
      dueDate,
      priority,
      tags,
      completed: false
    };

    data.tasks.push(task);
    await writeData(data);

    res.json(task);
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// Получение профиля
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const data = await readData();
    const user = data.users.find(u => u.userId === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { password, ...profile } = user;
    res.json(profile);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Обновление профиля
app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const { name, notificationsEnabled } = req.body;
    const data = await readData();

    const userIndex = data.users.findIndex(u => u.userId === req.userId);
    if (userIndex === -1) return res.status(404).json({ error: 'User not found' });

    if (name) data.users[userIndex].name = name;
    if (notificationsEnabled !== undefined) {
      data.users[userIndex].notificationsEnabled = notificationsEnabled;
    }

    await writeData(data);
    res.json({ success: true });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Получение уведомлений
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const data = await readData();
    const notifications = data.notifications.filter(n => n.userId === req.userId);
    res.json(notifications);
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ error: 'Failed to get notifications' });
  }
});

// Пометка уведомления как прочитанного
app.put('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const data = await readData();
    const notification = data.notifications.find(n => 
      n.notificationId === req.params.id && n.userId === req.userId
    );

    if (!notification) return res.status(404).json({ error: 'Notification not found' });

    notification.isRead = true;
    await writeData(data);

    res.json({ success: true });
  } catch (error) {
    console.error('Mark notification error:', error);
    res.status(500).json({ error: 'Failed to mark notification' });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
