import { Pool } from 'pg'

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  ssl: {
    rejectUnauthorized: false // Для Neon требуется SSL
  }
})

export default pool
