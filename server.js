const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors'); // Add this line to import the cors package
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Add CORS middleware - basic configuration (allows all origins)
app.use(cors());

// Alternatively, for more control you can configure specific origins:
/*
app.use(cors({
  origin: 'http://yourfrontenddomain.com', // or an array of allowed origins
  methods: ['GET', 'POST', 'DELETE'], // allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'] // allowed headers
}));
*/

// Create a MySQL connection pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root', // Replace with your MySQL username
    password: '8080', // Replace with your MySQL password
    database: 'mydatabase',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret_key'; // Replace with a strong secret key

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    //Token Extraction
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    //Token Check
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    //jwt.verify
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token.' });
        }
        req.user = user;
        next();
    });
}

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error' });
        }
        return res.status(201).json({ message: 'User registered successfully' });
    });
});

// POST /api/login - Login and get JWT token
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    //database query
    pool.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        
        //error handling
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error' });
        }

        //user existence check
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        return res.status(200).json({ token });
    });
});

// GET /api/people - Retrieve all people (Protected route)
app.get('/api/people', authenticateToken, (req, res) => {
    pool.query('SELECT * FROM people', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error' });
        }
        return res.status(200).json(results);
    });
});

// GET /api/people/:id - Retrieve a specific person by ID (Protected route)
app.get('/api/people/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    pool.query('SELECT * FROM people WHERE id = ?', [id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Person not found' });
        }
        return res.status(200).json(results[0]);
    });
});

// POST /api/people - Create a new person (Protected route)
app.post('/api/people', authenticateToken, (req, res) => {
    const { name, age } = req.body;
    if (!name || !age) {
        return res.status(400).json({ error: 'Name and age are required' });
    }

    pool.query('INSERT INTO people (name, age) VALUES (?, ?)', [name, age], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error' });
        }
        return res.status(201).json({ id: results.insertId, name, age });
    });
});

// DELETE /api/people/:id - Delete a person by ID (Protected route)
app.delete('/api/people/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    pool.query('DELETE FROM people WHERE id = ?', [id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ error: 'Person not found' });
        }
        return res.status(204).send(); // 204 No Content
    });
});

// Start the server
app.listen(8080, () => {
    console.log('Server is running on http://localhost:8080');
});