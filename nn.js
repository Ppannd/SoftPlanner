import pool from '../../lib/db'
import bcrypt from 'bcryptjs'

export default async function handler(req, res) {
  // Регистрация
  if (req.method === 'POST' && req.url === '/api/auth/register') {
    try {
      const { email, password } = req.body
      
      // Валидация
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' })
      }

      // Проверка существования пользователя
      const userExists = await pool.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      )
      
      if (userExists.rows.length > 0) {
        return res.status(400).json({ error: 'User already exists' })
      }

      // Хэширование пароля
      const hashedPassword = await bcrypt.hash(password, 10)
      
      // Генерация 6-значного ID (пример: "A1B2C3")
      const userId = Math.random().toString(36).substring(2, 8).toUpperCase()

      // Сохранение в БД
      await pool.query(
        'INSERT INTO users (id, email, password) VALUES ($1, $2, $3)',
        [userId, email, hashedPassword]
      )

      return res.status(201).json({ 
        success: true,
        userId 
      })

    } catch (error) {
      return res.status(500).json({ error: error.message })
    }
  }

  // Логин
  if (req.method === 'POST' && req.url === '/api/auth/login') {
    try {
      const { email, password } = req.body

      // Поиск пользователя
      const user = await pool.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      )
      
      if (user.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' })
      }

      // Проверка пароля
      const validPassword = await bcrypt.compare(
        password, 
        user.rows[0].password
      )
      
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid password' })
      }

      return res.status(200).json({ 
        success: true,
        userId: user.rows[0].id 
      })

    } catch (error) {
      return res.status(500).json({ error: error.message })
    }
  }

  // Ошибка для несуществующих роутов
  return res.status(404).json({ error: 'Route not found' })
}
