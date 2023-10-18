import mysql from 'mysql2/promise'; // Importing as ES Modules
import dotenv from 'dotenv';
dotenv.config();

const pool = mysql.createPool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_ID,
  connectionLimit: 10,
});

export default pool;
