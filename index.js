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

// API untuk registrasi user
app.post('/register', async (req, res) => {
  const { email, name, nim, password, role, confirmPassword } = req.body;

  console.log(req.body); // Cek data yang dikirim

  // Periksa apakah password dan konfirmasi password cocok
  if (!password || !confirmPassword) {
    return res.status(400).json({ error: 'Password is required' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    // Hash password sebelum disimpan di database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Simpan user ke database
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
    // Tangani error jika terjadi
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
    // Cari user berdasarkan email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Cek apakah password cocok
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    // Generate JWT untuk user yang berhasil login
    const token = jwt.sign(
      { email: user.email, id: user.id, role: user.role }, // Menambahkan role di payload
      process.env.JWT_SECRET, // Menggunakan JWT_SECRET dari environment
      { expiresIn: '1h' }
    );

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

// API untuk mengambil data pengguna
// API untuk mendapatkan data pengguna
app.get('/api/user', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, 'secretkey');
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
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
    res.status(403).json({ error: 'Invalid token' });
  }
});


// Jalankan server di port 4000
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
