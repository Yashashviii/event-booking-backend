import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import pkg from "pg";

dotenv.config();

const app = express();
const port = 4000;
const { Pool } = pkg;

// PostgreSQL pool setup
const pool = new Pool({
  database: process.env.DATABASE_NAME,
  user: process.env.DATABASE_USERNAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
  host: process.env.DATABASE_HOST,
});

// Middleware
app.use(bodyParser.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);

// Auth Middleware
const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();
};

app.get("/", (req, res) => {
  res.send("API is running...");
});

// Register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const userExists = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (userExists.rows.length)
      return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: "User registered" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (!user.rows.length)
      return res.status(400).json({ message: "Invalid email" });

    const valid = await bcrypt.compare(password, user.rows[0].password);
    if (!valid) return res.status(400).json({ message: "Invalid password" });

    req.session.userId = user.rows[0].id;
    res.status(200).json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create Event (Protected)
app.post("/events", isAuthenticated, async (req, res) => {
  const { name, date, capacity } = req.body;
  try {
    await pool.query(
      "INSERT INTO events (name, date, capacity, available_seats) VALUES ($1, $2, $3, $3)",
      [name, date, capacity]
    );
    res.status(201).json({ message: "Event created" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Events with Filter & Pagination
app.get("/events", async (req, res) => {
  const { start, end, page = 1, limit = 10 } = req.query;
  let query = "SELECT * FROM events WHERE 1=1";
  const values = [];
  let paramIndex = 1;

  if (start && end) {
    query += ` AND date BETWEEN $${paramIndex}::date AND $${
      paramIndex + 1
    }::date`;
    values.push(start, end);
    paramIndex += 2;
  }

  const offset = (page - 1) * limit;
  query += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
  values.push(limit, offset);

  try {
    const result = await pool.query(query, values);
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Event (Protected)
app.put("/events/:id", isAuthenticated, async (req, res) => {
  const { name, date, capacity } = req.body;
  try {
    await pool.query(
      "UPDATE events SET name = $1, date = $2, capacity = $3 WHERE id = $4",
      [name, date, capacity, req.params.id]
    );
    res.status(200).json({ message: "Event updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete Event (Protected)
app.delete("/events/:id", isAuthenticated, async (req, res) => {
  try {
    await pool.query("DELETE FROM events WHERE id = $1", [req.params.id]);
    res.status(200).json({ message: "Event deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
