require('dotenv').config();
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

// Путь к файлу данных
const DATA_FILE = path.join(__dirname, 'db.json');

// Инициализация файла данных
async function initData() {
  try {
    await fs.access(DATA_FILE);
  } catch {
    await fs.writeFile(DATA_FILE, JSON.stringify({
      users: [],
      tasks: [],
      passwordResets: []
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

// Инициализация при запуске
initData();

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
      tasks: []
    });

    await writeData(data);

    const token = jwt.sign({ userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });

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

    const token = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET || 'secret123', { expiresIn: '24h' });

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

// Запрос на сброс пароля
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const data = await readData();

    const user = data.users.find(u => u.email === email);
    if (!user) {
      return res.json({ success: true }); // Для безопасности не сообщаем, что email не найден
    }

    const resetToken = uuidv4();
    data.passwordResets.push({
      token: resetToken,
      email,
      expires: Date.now() + 3600000 // 1 час
    });

    await writeData(data);

    // В реальном приложении здесь бы отправлялось письмо
    console.log(`Password reset link: /reset-password?token=${resetToken}`);

    res.json({ success: true });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Сброс пароля
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const data = await readData();

    const resetRequest = data.passwordResets.find(r => r.token === token && r.expires > Date.now());
    if (!resetRequest) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const user = data.users.find(u => u.email === resetRequest.email);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    
    // Удаляем использованный токен
    data.passwordResets = data.passwordResets.filter(r => r.token !== token);
    
    await writeData(data);

    res.json({ success: true });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Отдача статических файлов
app.use(express.static(path.join(__dirname, '../')));

// Обработка всех остальных маршрутов для SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../', req.path));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
