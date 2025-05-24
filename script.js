const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Файл для хранения пользователей
const USERS_FILE = path.join(__dirname, 'users.json');

// Загрузка пользователей
function loadUsers() {
    try {
        return JSON.parse(fs.readFileSync(USERS_FILE));
    } catch {
        return [];
    }
}

// Сохранение пользователей
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Проверка аутентификации
function isAuthenticated(req) {
    return req.session && req.session.user;
}

// Маршруты
app.get('/', (req, res) => {
    res.redirect('/register.html');
});

app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const users = loadUsers();
    
    // Проверка существования пользователя
    if (users.some(u => u.email === email)) {
        return res.status(400).send('Email already registered');
    }
    
    // Добавление нового пользователя
    users.push({ name, email, password });
    saveUsers(users);
    
    res.redirect('/login.html');
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const users = loadUsers();
    
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) {
        return res.status(401).send('Invalid credentials');
    }
    
    res.redirect('/home.html');
});

// Запуск сервера
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});