const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Sample user data (in a real-world app, this would come from a database)
const users = [
    { id: 1, username: 'user1', password: '$2a$10$Nstt1RYLvFnk0KYrBcFV2u1YPwdX3mi7JvVReBBIXC5nU1q94vrq6' } // password is 'password'
];

// Register a new user
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // Check if username is already taken
        if (users.find(user => user.username === username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { id: users.length + 1, username, password: hashedPassword };
        users.push(user);
        res.status(201).json({ message: 'User registered successfully' });
    } catch {
        res.status(500).json({ message: 'An error occurred while registering the user' });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        // Find user by username
        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }
        // Compare password
        if (await bcrypt.compare(password, user.password)) {
            // Generate access token
            const accessToken = jwt.sign({ username: user.username }, 'secret');
            res.json({ accessToken });
        } else {
            res.status(401).json({ message: 'Incorrect password' });
        }
    } catch {
        res.status(500).json({ message: 'An error occurred while logging in' });
    }
});

// Protected route
app.get('/profile', authenticateToken, (req, res) => {
    res.send(`Welcome ${req.user.username}!`);
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401);
    }
    jwt.verify(token, 'secret', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Serve index.html as the homepage
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// npm init -y 
// npm i express
// npm i bcryptjs
// npm i jsonwebtoken
// npm start