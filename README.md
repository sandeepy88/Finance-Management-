// Backend (Node.js + Express + MongoDB) // Install dependencies: npm install express mongoose cors dotenv socket.io jsonwebtoken bcryptjs

const express = require('express'); const mongoose = require('mongoose'); const cors = require('cors'); const dotenv = require('dotenv'); const jwt = require('jsonwebtoken'); const bcrypt = require('bcryptjs'); const { Server } = require('socket.io'); const http = require('http');

dotenv.config(); const app = express(); const server = http.createServer(app); const io = new Server(server, { cors: { origin: '*' } });

app.use(cors()); app.use(express.json());

// MongoDB Connection mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema const UserSchema = new mongoose.Schema({ name: String, email: String, password: String }); const User = mongoose.model('User', UserSchema);

// Expense Schema const ExpenseSchema = new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, title: String, amount: Number, date: Date }); const Expense = mongoose.model('Expense', ExpenseSchema);

// User Registration app.post('/register', async (req, res) => { const { name, email, password } = req.body; const hashedPassword = await bcrypt.hash(password, 10); const user = new User({ name, email, password: hashedPassword }); await user.save(); res.json({ message: 'User registered' }); });

// User Login app.post('/login', async (req, res) => { const { email, password } = req.body; const user = await User.findOne({ email }); if (!user || !(await bcrypt.compare(password, user.password))) { return res.status(400).json({ message: 'Invalid credentials' }); } const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET); res.json({ token }); });

// Middleware for Authentication const auth = (req, res, next) => { const token = req.headers['authorization']; if (!token) return res.status(401).json({ message: 'Unauthorized' }); jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => { if (err) return res.status(403).json({ message: 'Invalid token' }); req.userId = decoded.userId; next(); }); };

// Expense Routes app.post('/expenses', auth, async (req, res) => { const expense = new Expense({ ...req.body, userId: req.userId }); await expense.save(); io.emit('expenseUpdate', expense); res.json(expense); });

app.get('/expenses', auth, async (req, res) => { const expenses = await Expense.find({ userId: req.userId }); res.json(expenses); });

app.put('/expenses/:id', auth, async (req, res) => { const expense = await Expense.findByIdAndUpdate(req.params.id, req.body, { new: true }); io.emit('expenseUpdate', expense); res.json(expense); });

app.delete('/expenses/:id', auth, async (req, res) => { await Expense.findByIdAndDelete(req.params.id); io.emit('expenseUpdate', { id: req.params.id, deleted: true }); res.json({ message: 'Deleted' }); });

// WebSocket Connection io.on('connection', (socket) => { console.log('User connected'); });

const PORT = process.env.PORT || 5000; server.listen(PORT, () => console.log(Server running on port ${PORT}));
