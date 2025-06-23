import pool from '../../lib/db'
import bcrypt from 'bcryptjs'
import Cors from 'cors'

// Инициализация CORS
const cors = Cors({
  methods: ['POST', 'OPTIONS'],
  origin: [
    'https://soft-planner-mlja.vercel.app',
    'http://localhost:3000' // Для локальной разработки
  ]
})

function runMiddleware(req, res, fn) {
  return new Promise((resolve, reject) => {
    fn(req, res, (result) => {
      if (result instanceof Error) return reject(result)
      return resolve(result)
    })
  })
}

export default async function handler(req, res) {
  // Обрабатываем CORS
  await runMiddleware(req, res, cors)

  // Логируем входящий запрос
  console.log('\n[REQUEST]', req.method, req.url)
  console.log('Headers:', req.headers)
  console.log('Body:', req.body)

  try {
    // Регистрация
    if (req.method === 'POST' && req.url === '/api/auth/register') {
      const { email, password } = req.body

      // Валидация
      if (!email || !password) {
        console.log('[ERROR] Validation failed')
        return res.status(400).json({ 
          success: false,
          error: 'Email and password are required' 
        })
      }

      // Проверка формата email
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid email format'
        })
      }

      // Проверка длины пароля
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          error: 'Password must be at least 6 characters'
        })
      }

      // Проверка существования пользователя
      const userExists = await pool.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      )
      
      if (userExists.rows.length > 0) {
        console.log('[ERROR] User already exists')
        return res.status(409).json({ 
          success: false,
          error: 'User already exists' 
        })
      }

      // Хэширование пароля
      const hashedPassword = await bcrypt.hash(password, 10)
      
      // Генерация ID
      const userId = Math.random().toString(36).substring(2, 8).toUpperCase()

      // Сохранение в БД
      await pool.query(
        'INSERT INTO users (id, email, password) VALUES ($1, $2, $3)',
        [userId, email, hashedPassword]
      )

      console.log('[SUCCESS] User registered:', userId)
      return res.status(201).json({ 
        success: true,
        userId 
      })
    }

    // Авторизация
    if (req.method === 'POST' && req.url === '/api/auth/login') {
      const { email, password } = req.body

      // Валидация
      if (!email || !password) {
        return res.status(400).json({ 
          success: false,
          error: 'Email and password are required' 
        })
      }

      // Поиск пользователя
      const userResult = await pool.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      )
      
      if (userResult.rows.length === 0) {
        console.log('[ERROR] User not found')
        return res.status(404).json({ 
          success: false,
          error: 'User not found' 
        })
      }

      const user = userResult.rows[0]

      // Проверка пароля
      const isPasswordValid = await bcrypt.compare(password, user.password)
      
      if (!isPasswordValid) {
        console.log('[ERROR] Invalid password')
        return res.status(401).json({ 
          success: false,
          error: 'Invalid password' 
        })
      }

      console.log('[SUCCESS] User logged in:', user.id)
      return res.status(200).json({ 
        success: true,
        userId: user.id 
      })
    }

    // Неподдерживаемый метод
    return res.status(405).json({ 
      success: false,
      error: 'Method not allowed' 
    })

  } catch (error) {
    console.error('[SERVER ERROR]', error)
    return res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    })
  }
}
