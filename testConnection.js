const { Client } = require('pg');

// Ganti dengan URL koneksi database Anda
const client = new Client({
  connectionString: "postgresql://postgres.emxbpnrytsgvboekphhy:CloudComputing12345.@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres",
});

client.connect()
  .then(() => {
    console.log("Berhasil terhubung ke database");
  })
  .catch(err => {
    console.error("Kesalahan koneksi", err.stack);
  })
  .finally(() => {
    client.end();
  });
