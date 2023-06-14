const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const usersData = require('./userData')

const app = express();
app.use(express.json());

const users = usersData;

// User Registration
app.post('/register', (req, res) => {
  const { email, password, phoneNumber } = req.body;

  // Check if user already exists
  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(409).json({ message: 'User already exists' });
  }

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ message: 'Error occurred while hashing password' });
    }

    // Create a new user object
    const newUser = {
      email: email,
      password: hashedPassword,
      phoneNumber: phoneNumber,
    };

    // Add the user to the users array
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully' });
  });
});

// User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Compare the password
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate a JWT token
    const token = jwt.sign({ email: user.email }, 'secret_key');

    res.status(200).json({ message: 'Login successful', token: token });
  });
});

// Get all registered users
app.get('/users', (req, res) => {
  res.status(200).json(users);
});

// Get a single user by email
app.get('/users/:email', (req, res) => {
  const email = req.params.email;
  const user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.status(200).json(user);
});

// Protected Route
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Accessed protected profile route' });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
}

// Start the server
app.listen(5000, () => {
  console.log('Server started on port 5000');
});
