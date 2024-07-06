const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { sequelize, User, Appointment } = require('./models');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = "your_secret_key";

// Signup
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, password: hashedPassword });
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Username already exists' });
    }
});

// Signin
app.post('/signin', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Book appointment
app.post('/appointments', authenticateToken, async (req, res) => {
    const { date, time } = req.body;
    const userId = req.user.userId;
    try {
        const appointment = await Appointment.create({ userId, date, time });
        res.status(201).json(appointment);
    } catch (error) {
        res.status(400).json({ error: 'Failed to create appointment' });
    }
});

// Get appointments
app.get('/appointments', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const appointments = await Appointment.findAll({ where: { userId } });
    res.json(appointments);
});

// Error handling for non-existent routes
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
