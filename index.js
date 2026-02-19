// --- BAGIAN 1: PAKSA IPV4 & LOGGING DNS ---
const dns = require('node:dns');
try {
    dns.setDefaultResultOrder('ipv4first'); // Paksa IPv4
    console.log("✅ DNS Order set to: ipv4first");
} catch (e) {
    console.log("⚠️ Node version old, skipping DNS order");
}

// Debug: Cek IP apa yang dituju
dns.lookup('smtp.gmail.com', { family: 4 }, (err, address, family) => {
    if (err) console.error('❌ DNS Lookup Failed:', err);
    else console.log(`🔍 Resolving smtp.gmail.com -> IP: ${address} (IPv${family})`);
});
// -------------------------------------------

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- BAGIAN 2: KONFIGURASI SMTP PORT 465 (SSL) ---
// Kita ganti ke Port 465 karena lebih jarang kena timeout di Railway
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,       // Ganti ke 465 (SSL)
    secure: true,    // TRUE untuk 465
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD // Pastikan tanpa spasi di Railway Variable
    },
    tls: {
        rejectUnauthorized: false // Bypass masalah sertifikat
    },
    // Timeout Setting diperpanjang
    connectionTimeout: 20000, // 20 Detik
    greetingTimeout: 20000,
    socketTimeout: 20000
});

// Cek Koneksi
console.log("⏳ Mencoba menghubungi Gmail...");
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Gagal koneksi ke Gmail:', error);
    } else {
        console.log('✅ BERHASIL: Siap mengirim email');
    }
});

// --- ROUTES ---

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/send-otp', async (req, res) => {
    try {
        let { email } = req.body;
        if (!email) return res.status(400).json({ success: false });

        email = email.toLowerCase().trim();
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Database Logic
        await supabase.from('otp_codes').update({ used: true }).eq('email', email);
        const { error } = await supabase.from('otp_codes').insert({
            email, code: otp, expires_at: new Date(Date.now() + 5 * 60000).toISOString()
        });
        if (error) throw error;

        // Kirim Email
        await transporter.sendMail({
            from: `"Support App" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Kode OTP',
            html: `<h1>Kode OTP: ${otp}</h1>`
        });

        console.log(`Email sent to ${email}`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- REGISTER ---
app.post('/register', async (req, res) => {
    try {
        const { full_name, email, phone_number, password, otp, role } = req.body;

        // 1. Verifikasi OTP
        const { data: otpData, error: otpError } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('code', otp)
            .eq('used', false)
            .gt('expires_at', new Date().toISOString())
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({ success: false, message: 'OTP Salah atau Kadaluarsa' });
        }

        // 2. Tandai OTP sudah dipakai
        await supabase.from('otp_codes').update({ used: true }).eq('id', otpData.id);

        // 3. Cek User Exist di Table Public
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .or(`email.eq.${email},phone_number.eq.${phone_number}`)
            .single();

        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email atau No HP sudah terdaftar' });
        }

        // 4. Register ke Supabase Auth (Optional, tapi bagus untuk security)
        // Kita pakai password hash manual di table user untuk simplicitas sesuai request awal
        // Tapi best practice tetap sync ke Auth. Di sini kita fokus ke Table Users dulu.

        const hashedPassword = await bcrypt.hash(password, 10);

        // 5. Simpan ke Table Users
        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert({
                email,
                phone_number,
                full_name,
                password_hash: hashedPassword,
                user_role: [role], // Array
                is_verified: true // Karena sudah verify OTP
            })
            .select()
            .single();

        if (insertError) throw insertError;

        res.json({ success: true, message: 'Registrasi Berhasil', user: newUser });

    } catch (err) {
        console.error("Register Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- LOGIN ---
app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body; // identifier = email OR phone

        // Cari user by Email OR Phone
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`email.eq.${identifier},phone_number.eq.${identifier}`)
            .single();

        if (error || !user) {
            return res.status(400).json({ success: false, message: 'User tidak ditemukan' });
        }

        // Cek Password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ success: false, message: 'Password Salah' });
        }

        res.json({ success: true, message: 'Login Berhasil', user });

    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});