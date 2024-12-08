const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');

// Inisialisasi Prisma Client
const prisma = new PrismaClient();

const app = express();
app.use(express.json());
app.use(cors());

// Middleware untuk autentikasi JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, 'secretkey');
    req.user = decoded; // Simpan data user ke req
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Middleware untuk memverifikasi role admin
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Admins only' });
  }
  next();
};

// API untuk registrasi user
app.post('/register', async (req, res) => {
  const { email, name, nim, password, role, confirmPassword } = req.body;

  console.log(req.body); // Cek data yang dikirim

  if (!password || !confirmPassword) {
    return res.status(400).json({ error: 'Password is required' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        email,
        name,
        nim,
        role,
        password: hashedPassword,
      },
    });

    res.json({ message: 'User registered successfully', user: newUser });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user: ' + error.message });
  }
});

// API untuk login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ email: user.email, id: user.id, role: user.role }, 'secretkey', {
      expiresIn: '1h',
    });

    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: 'Error logging in: ' + error.message });
  }
});

// API untuk memverifikasi token JWT
app.get('/verify-token', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, 'secretkey');
    res.json({ message: 'Token is valid', user: decoded });
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

// API untuk mendapatkan data pengguna (user yang sedang login)
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        name: true,
        email: true,
        nim: true,
        role: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(403).json({ error: 'Error fetching user: ' + error.message });
  }
});

// API untuk mendapatkan semua user
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, name: true, email: true, nim: true, role: true }, // Tentukan kolom yang ditampilkan
    });

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users: ' + error.message });
  }
});

// API untuk menghapus user berdasarkan ID (hanya untuk admin)
app.delete('/api/user/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const user = await prisma.user.findUnique({ where: { id: Number(id) } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    await prisma.user.delete({ where: { id: Number(id) } });
    res.json({ message: `User with ID ${id} has been deleted.` });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting user: ' + error.message });
  }
});

// Jalankan server di port 4000
app.listen(4000, () => {
  console.log('Server running on port 4000');
});
