const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const dotenv=require('dotenv');
dotenv.config();

const app = express();
const PORT = 5000;

const config = {
  connectionString: process.env.DATABASE_URL,
}


const pool = new Pool(config);


app.use(cors({
  origin: "http://localhost:5173", // frontend
  credentials: true,
}));

app.use(express.json());
app.use(session({
  secret: process.env.secret,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}));

app.use(async (req, res, next) => {
  if (req.session.userId) {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.session.userId]);
    if (rows.length > 0) req.user = rows[0];
  }
  next();
});

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    await pool.query("INSERT INTO users (name, email, password_hash, status) VALUES ($1, $2, $3, 'active')", [name, email, hash]);
    await pool.query("UPDATE users SET last_login = NOW() WHERE email = $1", [email]);
    res.sendStatus(201);
  } catch (err) {
    console.log(err);
    res.status(400).send("Email already exists");
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send("Invalid email or password");
  }
  if (user.status === "blocked") return res.status(403).send("Blocked");
  req.session.userId = user.id;


  await pool.query("UPDATE users SET last_login = NOW() WHERE id = $1", [user.id]);
  res.json(user);
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.sendStatus(200));
});

// Forgot Password
app.patch("/api/forgot-password", async (req, res) => {
  const { email, newPassword } = req.body;
  console.log(email, newPassword);
  const hash = await bcrypt.hash(newPassword, 10);
  const { rowCount } = await pool.query("UPDATE users SET password_hash = $1 WHERE email = $2", [hash, email]);
  await pool.query("UPDATE users SET last_login = NOW() WHERE email = $1", [email]);
  if (rowCount === 0) return res.status(404).send("User not found")
  res.send("Password updated");
});

// For table
app.get("/api/users", async (req, res) => {
  if (!req.user) return res.sendStatus(401);
  const { rows } = await pool.query("SELECT id, name, email, status, last_login FROM users ORDER BY id ASC");
  res.json(rows);
});

// Block, Unblock, Delete
app.patch("/api/users/:action", async (req, res) => {
  const { action } = req.params;
  const { ids } = req.body;
  if (!req.user) return res.sendStatus(401);

  const queryMap = {
    block: "UPDATE users SET status = 'blocked' WHERE id = ANY($1)",
    unblock: "UPDATE users SET status = 'active' WHERE id = ANY($1)",
    delete: "DELETE FROM users WHERE id = ANY($1)",
  };

  const query = queryMap[action];
  if (!query) return res.status(400).send("Invalid action");

  await pool.query(query, [ids]);
  res.send(`${action} successful`);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
