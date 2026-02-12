require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer'); // <--- INI WAJIB ADA DI ATAS
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

// Supabase Admin client
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

// --- KONFIGURASI SMTP GMAIL (FIX RAILWAY IPV4) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // Wajib false untuk port 587
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
    },
    // Opsi TLS untuk mencegah error sertifikat
    tls: {
        rejectUnauthorized: false
    },
    // --- BAGIAN PENTING (FIX TIMEOUT) ---
    family: 4,              // Memaksa Node.js pakai IPv4 (Solusi Timeout Railway)
    connectionTimeout: 10000, // Tunggu koneksi max 10 detik
    greetingTimeout: 5000,    // Tunggu sapaan server max 5 detik
    logger: true,             // Aktifkan log supaya terlihat di terminal Railway
    debug: true               // Aktifkan mode debug
});

// Verifikasi koneksi email saat server start
transporter.verify(function (error, success) {
    if (error) {
        console.error('❌ Gagal koneksi ke Gmail:', error);
    } else {
        console.log('✅ Siap mengirim email');
    }
});
// -----------------------------------

// Generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Send OTP endpoint
app.post('/send-otp', async (req, res) => {
    try {
        let { email } = req.body;
        if (email) email = email.toLowerCase();

        if (!email) {
            return res.status(400).json({ success: false, message: 'Email diperlukan' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Format email tidak valid' });
        }

        // Cek OTP existing (Anti Spam)
        const { data: existingOTP } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('used', false)
            .gte('created_at', new Date(Date.now() - 60 * 1000).toISOString())
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        let otp;
        let expiresAt;

        if (existingOTP) {
            console.log(`Resending EXISTING OTP to ${email}`);
            otp = existingOTP.code;
        } else {
            otp = generateOTP();
            expiresAt = new Date(Date.now() + 5 * 60 * 1000);

            await supabase
                .from('otp_codes')
                .update({ used: true })
                .eq('email', email)
                .eq('used', false);

            const { error: dbError } = await supabase
                .from('otp_codes')
                .insert({
                    email: email,
                    code: otp,
                    expires_at: expiresAt.toISOString(),
                    used: false
                });

            if (dbError) {
                console.error('Database error:', dbError);
                return res.status(500).json({ success: false, message: 'Gagal menyimpan OTP' });
            }
        }

        const mailOptions = {
            from: `"Aplikasi Tukang PUPR" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Kode OTP Anda - Aplikasi Tukang PUPR Jogja',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1976D2;">Aplikasi Tukang PUPR Jogja</h2>
          <p>Berikut adalah kode OTP Anda:</p>
          <div style="background-color: #f5f5f5; padding: 20px; text-align: center; border-radius: 8px;">
            <h1 style="font-size: 36px; letter-spacing: 8px; color: #333; margin: 0;">${otp}</h1>
          </div>
          <p style="color: #666; margin-top: 20px;">
            Kode ini berlaku selama <strong>5 menit</strong>.
          </p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);
        console.log(`OTP sent to ${email}`);
        res.json({ success: true, message: 'Kode OTP telah dikirim ke email Anda' });

    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).json({ success: false, message: 'Gagal mengirim email OTP' });
    }
});

// Verify OTP endpoint
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ success: false, message: 'Email dan OTP diperlukan' });

        const { data: otpData, error: fetchError } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('code', otp)
            .eq('used', false)
            .gte('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (fetchError || !otpData) {
            return res.status(400).json({ success: false, message: 'Kode OTP tidak valid atau sudah kadaluarsa' });
        }

        await supabase.from('otp_codes').update({ used: true }).eq('id', otpData.id);
        res.json({ success: true, message: 'OTP berhasil diverifikasi' });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ success: false, message: 'Gagal memverifikasi OTP' });
    }
});

// Register Endpoint
app.post('/register', async (req, res) => {
    try {
        let { email, phone_number, full_name, password, otp, role } = req.body;
        if (email) email = email.toLowerCase();
        if (!email || !phone_number || !full_name || !password || !otp || !role) {
            return res.status(400).json({ success: false, message: 'Semua field wajib diisi' });
        }

        const { data: otpData } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('code', otp)
            .eq('used', false)
            .gte('expires_at', new Date().toISOString())
            .single();

        if (!otpData) return res.status(400).json({ success: false, message: 'Kode OTP tidak valid' });

        let userId;
        const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
            email: email, password: password, email_confirm: true
        });

        if (authError) {
            if (authError.message.includes('already registered')) {
                const { data: loginData } = await supabase.auth.signInWithPassword({ email, password });
                if (!loginData.user) return res.status(400).json({ success: false, message: 'Email sudah terdaftar.' });
                userId = loginData.user.id;
            } else {
                return res.status(400).json({ success: false, message: authError.message });
            }
        } else {
            userId = authData.user.id;
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const { error: userError } = await supabaseAdmin.from('users').insert({
            id: userId, email, phone_number, full_name, password_hash: passwordHash, is_verified: true, user_role: [role]
        });

        if (userError) {
            if (!authError) await supabaseAdmin.auth.admin.deleteUser(userId);
            return res.status(400).json({ success: false, message: 'Gagal insert user: ' + userError.message });
        }

        await supabase.from('otp_codes').update({ used: true }).eq('id', otpData.id);
        res.json({ success: true, message: 'Registrasi berhasil' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        if (!identifier || !password) return res.status(400).json({ success: false, message: 'Lengkapi data' });

        const { data: user } = await supabase
            .from('users')
            .select('*')
            .or(`email.eq.${identifier},phone_number.eq.${identifier}`)
            .eq('is_verified', true)
            .maybeSingle();

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ success: false, message: 'Email/HP atau password salah' });
        }

        res.json({ success: true, message: 'Login berhasil', user: { id: user.id, full_name: user.full_name, role: user.user_role } });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Gagal login' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 OTP Server running on port ${PORT}`);
});