require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Create all tables on startup
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'tenant',
        plan VARCHAR(20) DEFAULT 'free',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS properties (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        address TEXT,
        rent_amount DECIMAL(10,2),
        geofence_radius INTEGER DEFAULT 200,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS contractors (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255),
        pay_rate DECIMAL(10,2),
        billing_rate DECIMAL(10,2),
        plan VARCHAR(20) DEFAULT 'free',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS time_entries (
        id SERIAL PRIMARY KEY,
        contractor_id INTEGER REFERENCES contractors(id),
        property_id INTEGER REFERENCES properties(id),
        clock_in TIMESTAMP,
        clock_out TIMESTAMP,
        clock_in_lat DECIMAL(10,8),
        clock_in_lng DECIMAL(11,8),
        offsite_flag BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        description TEXT,
        debit DECIMAL(10,2) DEFAULT 0,
        credit DECIMAL(10,2) DEFAULT 0,
        category VARCHAR(100),
        property_id INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('All tables ready');
  } catch (e) { console.error(e); }
})();

// Auth
app.post('/api/auth', async (req, res) => {
  const { email, password } = req.body;
  let user = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!user) {
    const hash = await bcrypt.hash(password, 10);
    user = (await pool.query(
      'INSERT INTO users(email,password,role) VALUES($1,$2,$3) RETURNING id,email,role,plan',
      [email, hash, 'admin']
    )).rows[0];
  } else if (!await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, 'supersecret');
  res.json({ token, user: { id: user.id, email: user.email, role: user.role, plan: user.plan } });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const host = '0.0.0.0';
const port = process.env.PORT || 3000;
app.listen(port, host, () => console.log(`Running on ${host}:${port}`));
