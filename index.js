// --- BAGIAN INI SANGAT PENTING (JANGAN DIHAPUS) ---
// Memaksa Node.js menggunakan IPv4 agar tidak timeout di Railway
const dns = require('node:dns');
try {
    dns.setDefaultResultOrder('ipv4first');
} catch (e) {
    console.log('Node version too old for setDefaultResultOrder, skipping...');
}
// ---------------------------------------------------

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase Setup
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

// --- CONFIG SMTP (Gunakan Port 587 + Opsi Kompatibilitas) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // False untuk port 587
    auth: {
        user: process.env.GMAIL_USER,
        // Pastikan di Railway variable passwordnya TANPA SPASI
        pass: process.env.GMAIL_APP_PASSWORD
    },
    tls: {
        rejectUnauthorized: false
    },
    // Tambahan untuk mencegah timeout
    greetingTimeout: 20000,
    socketTimeout: 20000,
    connectionTimeout: 20000
});

// Cek koneksi saat server nyala
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Gagal koneksi ke Gmail:', error);
    } else {
        console.log('✅ BERHASIL: Siap mengirim email');
    }
});

// --- ROUTES ---

app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
});

app.post('/send-otp', async (req, res) => {
    try {
        let { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: 'Email wajib' });

        email = email.toLowerCase().trim();
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // 1. Invalidate OTP lama
        await supabase.from('otp_codes').update({ used: true }).eq('email', email);

        // 2. Simpan OTP baru
        const { error } = await supabase.from('otp_codes').insert({
            email,
            code: otp,
            expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
            used: false
        });

        if (error) throw error;

        // 3. Kirim Email
        await transporter.sendMail({
            from: `"Aplikasi Tukang" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Kode OTP Masuk',
            html: `<h2>Kode OTP Anda: <b>${otp}</b></h2><p>Berlaku 5 menit.</p>`
        });

        console.log(`Email terkirim ke ${email}`);
        res.json({ success: true, message: 'OTP Terkirim' });

    } catch (err) {
        console.error('Send OTP Error:', err);
        res.status(500).json({ success: false, message: 'Gagal: ' + err.message });
    }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const { data } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('code', otp)
            .eq('used', false)
            .gte('expires_at', new Date().toISOString())
            .maybeSingle();

        if (!data) return res.status(400).json({ success: false, message: 'OTP Invalid' });

        await supabase.from('otp_codes').update({ used: true }).eq('id', data.id);
        res.json({ success: true, message: 'Verified' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error' });
    }
});

// Register
app.post('/register', async (req, res) => {
    try {
        const { email, password, full_name, phone_number, role, otp } = req.body;

        // Cek OTP lagi (Opsional, tapi aman)
        const { data: otpValid } = await supabase
            .from('otp_codes')
            .select('id')
            .eq('email', email)
            .eq('code', otp)
            .eq('used', true) // Asumsi sudah di-verify di endpoint /verify-otp
            .maybeSingle();

        // Buat User Auth
        let userId;
        const { data: auth, error: authErr } = await supabaseAdmin.auth.admin.createUser({
            email, password, email_confirm: true
        });

        if (authErr) {
            if (authErr.message.includes('already registered')) {
                const { data: login } = await supabase.auth.signInWithPassword({ email, password });
                if (!login.user) return res.status(400).json({ success: false, message: 'Email sudah ada.' });
                userId = login.user.id;
            } else {
                throw authErr;
            }
        } else {
            userId = auth.user.id;
        }

        // Simpan Data User
        const { error: userErr } = await supabaseAdmin.from('users').insert({
            id: userId,
            email, full_name, phone_number,
            user_role: [role],
            password_hash: await bcrypt.hash(password, 10),
            is_verified: true
        });

        if (userErr) {
            if (!authErr) await supabaseAdmin.auth.admin.deleteUser(userId);
            return res.status(400).json({ success: false, message: 'Gagal simpan user' });
        }

        res.json({ success: true, message: 'Registrasi Berhasil' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const { data: user } = await supabase.from('users')
            .select('*')
            .or(`email.eq.${identifier},phone_number.eq.${identifier}`)
            .maybeSingle();

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ success: false, message: 'Login Gagal' });
        }
        res.json({ success: true, message: 'Login Berhasil', user });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});