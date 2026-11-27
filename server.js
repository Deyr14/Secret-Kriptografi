const express = require('express');
const crypto = require('crypto');
const path = require('path');
const dotenv = require('dotenv');
const db = require('./database/database');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '100kb' }));

// Sajikan file frontend (index.html, baca.html, crypto.js) dari folder public
app.use(express.static(path.join(__dirname, 'public')));

// Endpoint menyimpan pesan terenkripsi
app.post('/api/secrets', (req, res) => {
  try {
    const { ciphertext, iv } = req.body;

    if (
      typeof ciphertext !== 'string' ||
      !ciphertext.trim() ||
      typeof iv !== 'string' ||
      !iv.trim()
    ) {
      return res.status(400).json({
        error: 'Ciphertext dan IV wajib diisi'
      });
    }

    // Membuat token acak 256-bit (64 karakter hex)
    const token = crypto.randomBytes(32).toString('hex');

    // Menyimpan pesan terenkripsi ke database
    db.prepare(`
      INSERT INTO secrets (token, ciphertext, iv)
      VALUES (?, ?, ?)
    `).run(token, ciphertext, iv);

    res.status(201).json({
      message: 'Pesan berhasil disimpan',
      token: token,
      link: `/baca.html?token=${token}`
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Gagal menyimpan pesan'
    });
  }
});

// Endpoint membaca dan menghancurkan pesan
app.get('/api/secrets/:token', (req, res) => {
  try {
    const { token } = req.params;

    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(400).json({
        error: 'Token tidak valid'
      });
    }

    // Ambil dan hapus pesan dalam satu transaksi
    const consumeSecret = db.transaction(() => {
      const secret = db.prepare(`
        SELECT ciphertext, iv
        FROM secrets
        WHERE token = ?
      `).get(token);

      if (!secret) {
        return null;
      }

      db.prepare(`
        DELETE FROM secrets
        WHERE token = ?
      `).run(token);

      return secret;
    });

    const secret = consumeSecret();

    if (!secret) {
      return res.status(404).json({
        error: 'Pesan tidak ditemukan atau sudah dihancurkan'
      });
    }

    res.json({
      message: 'Pesan berhasil diambil',
      ciphertext: secret.ciphertext,
      iv: secret.iv
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Gagal mengambil pesan'
    });
  }
});

// Menjalankan server
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});