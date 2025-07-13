# 🕵️ Telegram Steganography Bot

Bot Telegram ini memungkinkan Anda menyembunyikan pesan rahasia ke dalam gambar menggunakan **steganografi**, dengan pesan yang telah dienkripsi secara hybrid menggunakan **RSA** dan **AES**. Bot juga mendukung manajemen kunci publik untuk setiap pengguna.

---

## ✨ Fitur

* 🔐 Enkripsi hybrid (AES + RSA)
* 🖼️ Steganografi LSB (Least Significant Bit)
* 🔑 Manajemen kunci publik (simpan, hapus, lihat)
* 🤖 UI Bot Telegram yang interaktif

---

## 📆 Instalasi

Pastikan Anda menggunakan **Python 3.9+**.

1. Clone repositori ini:

```bash
git clone https://github.com/username/steganography-bot.git
cd steganography-bot
```

2. Instal dependensi:

```bash
pip install -r requirements.txt
```

> Jika belum ada `requirements.txt`, gunakan ini:

```bash
pip install python-telegram-bot==20.0 Pillow pycryptodome
```

---

## 🔑 Konfigurasi Token

1. Buat bot melalui [@BotFather](https://t.me/BotFather)
2. Salin **API token**
3. Buka `main.py` dan ganti baris berikut:

```python
TOKEN = "GANTI_DENGAN_TOKEN_BOT_ANDA"
```

---

## ▶️ Menjalankan Bot

```bash
python main.py
```

Bot akan berjalan dan menunggu perintah melalui Telegram.

---

## 📋 Panduan Penggunaan

### 🛡️ 1. Generate Kunci

```bash
/generatekeys
```

Bot akan mengirimkan:

* `private.pem` (RAHASIA, simpan baik-baik)
* `public.pem` (bagikan ke pengirim)

---

### 📂 2. Simpan Kunci Publik

```bash
/savekey
```

Lalu:

1. Masukkan label (misalnya: `Budi`)
2. Kirim file `public.pem` milik Budi

---

### ✉️ 3. Sembunyikan Pesan ke dalam Gambar

```bash
/embed
```

Ikuti langkah berikut:

1. Pilih kunci publik penerima
2. Kirim pesan rahasia
3. Upload gambar (*as document*) format `.png`
4. Masukkan password steganografi

Bot akan membalas dengan gambar yang berisi pesan tersembunyi.

---

### 🔍 4. Ekstrak Pesan dari Gambar

```bash
/extract
```

Ikuti langkah:

1. Kirim file `private.pem` Anda
2. Upload gambar tersembunyi (*as document*)
3. Masukkan password steganografi

Jika sukses, pesan akan ditampilkan.

---

### 📚 5. Fitur Tambahan

* **/listkeys** – Menampilkan daftar label kunci publik
* **/deletekey** – Menghapus salah satu kunci publik
* **/cancel** – Membatalkan proses aktif

---

## 📁 Struktur Proyek

```
📆 steganography-bot
ꂳ 📌 main.py
ꂳ 📌 README.md
ꂳ 📌 user_keys.json  ← dibuat otomatis
```

---

## ⚠️ Peringatan

* Jangan bagikan `private.pem` ke siapa pun.
* Simpan file kunci RSA Anda di tempat aman.
* Gambar yang digunakan **harus berformat PNG** dan dikirim sebagai **dokumen**, bukan sebagai foto biasa di Telegram.

---

## 🧐 Penjelasan Teknis

* **Enkripsi**: AES-128 (EAX mode) untuk isi pesan, RSA-2048 untuk kunci sesi.
* **Steganografi**: Penyisipan bit dilakukan pada channel warna gambar (RGB) secara acak berdasarkan password.
* **Keamanan**: Tanpa password steganografi dan kunci privat, pesan tidak bisa dibaca.

---

## 🙋‍♂️ Kontribusi

Pull request sangat diterima! Untuk perubahan besar, harap buka issue terlebih dahulu untuk mendiskusikan perubahan.
