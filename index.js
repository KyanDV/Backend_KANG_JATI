// Konfigurasi SMTP Gmail untuk Railway (Port 587)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // Wajib false untuk port 587
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
    },
    tls: {
        ciphers: 'SSLv3', // Kadang diperlukan untuk kompatibilitas
        rejectUnauthorized: false // Mencegah error sertifikat di server cloud
    }
});