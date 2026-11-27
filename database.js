
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(
  path.join(__dirname, 'secrets.db')
);

// Membuat tabel penyimpanan pesan rahasia
db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

console.log('Database berhasil terhubung!');

module.exports = db;
