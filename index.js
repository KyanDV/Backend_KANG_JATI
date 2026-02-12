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

// Supabase client (Anon Key - untuk read publik/RLS)
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

// Supabase Admin client (Service Role - untuk Auth & Write bypass RLS)
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

// --- PERBAIKAN CONFIG SMTP ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465, // Gunakan Port 465 untuk koneksi SSL langsung
    secure: true, // True untuk port 465
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD // Wajib App Password
    },
    // Hapus ciphers SSLv3 yang bikin error
    tls: {
        rejectUnauthorized: false // Membantu koneksi di cloud environment
    },
    family: 4 // Force IPv4 untuk mencegah timeout IPv6 di Railway
});

// Verifikasi koneksi email saat server start
transporter.verify(function (error, success) {
    if (error) {
        console.error('❌ Gagal koneksi ke Gmail:', error);
    } else {
        console.log('✅ Siap mengirim email');
    }
});
// -----------------------------

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
            .gte('created_at', new Date(Date.now() - 60 * 1000).toISOString()) // 60 detik terakhir
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        let otp;
        let expiresAt;

        if (existingOTP) {
            console.log(`Resending EXISTING OTP to ${email}`);
            otp = existingOTP.code;
        } else {
            // Generate OTP Baru
            otp = generateOTP();
            expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 menit

            // Matikan OTP lama
            await supabase
                .from('otp_codes')
                .update({ used: true })
                .eq('email', email)
                .eq('used', false);

            // Simpan OTP Baru
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

        // Template Email
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
            Kode ini berlaku selama <strong>5 menit</strong>.<br>
            Jangan bagikan kode ini kepada siapapun.
          </p>
        </div>
      `
        };

        // Kirim Email
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

        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'Email dan OTP diperlukan' });
        }

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
            return res.status(400).json({
                success: false,
                message: 'Kode OTP tidak valid atau sudah kadaluarsa'
            });
        }

        // Mark OTP as used
        await supabase
            .from('otp_codes')
            .update({ used: true })
            .eq('id', otpData.id);

        res.json({ success: true, message: 'OTP berhasil diverifikasi' });

    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ success: false, message: 'Gagal memverifikasi OTP' });
    }
});

app.post('/register', async (req, res) => {
    try {
        let { email, phone_number, full_name, password, otp, role } = req.body;
        if (email) email = email.toLowerCase();

        if (!email || !phone_number || !full_name || !password || !otp || !role) {
            return res.status(400).json({
                success: false,
                message: 'Semua field wajib diisi (termasuk OTP)'
            });
        }

        // 1. Verify OTP
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
            return res.status(400).json({
                success: false,
                message: 'Kode OTP tidak valid atau sudah kadaluarsa'
            });
        }

        // 2. Create User in Supabase Auth (Admin)
        let userId;
        const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
            email: email,
            password: password,
            email_confirm: true
        });

        if (authError) {
            if (authError.message.includes('already registered') || authError.status === 422) {
                console.log('User exists in Auth, trying recovery...');

                // Cek user di public table
                const { data: existingPublicUser } = await supabase
                    .from('users')
                    .select('id')
                    .eq('email', email)
                    .maybeSingle();

                if (existingPublicUser) {
                    return res.status(400).json({ success: false, message: 'Email sudah terdaftar sepenuhnya.' });
                }

                // Coba recover ID lewat login
                const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({
                    email: email,
                    password: password
                });

                if (loginError || !loginData.user) {
                    return res.status(400).json({
                        success: false,
                        message: 'Email terdaftar di Auth tapi gagal login. Password mungkin beda.'
                    });
                }
                userId = loginData.user.id;
            } else {
                return res.status(400).json({
                    success: false,
                    message: 'Gagal membuat akun Auth: ' + authError.message
                });
            }
        } else {
            userId = authData.user.id;
        }

        // 3. Hash password (legacy support)
        const passwordHash = await bcrypt.hash(password, 12);

        // 4. Create User in public.users
        const { error: userError } = await supabaseAdmin // Gunakan Admin client untuk bypass RLS insert
            .from('users')
            .insert({
                id: userId,
                email,
                phone_number,
                full_name,
                password_hash: passwordHash,
                is_verified: true,
                user_role: [role],
            });

        if (userError) {
            // Rollback Auth jika insert DB gagal (hanya jika user baru dibuat)
            if (!authError) await supabaseAdmin.auth.admin.deleteUser(userId);

            if (userError.code === '23505') {
                return res.status(400).json({
                    success: false,
                    message: 'Email atau Nomor HP sudah terdaftar'
                });
            }
            throw userError;
        }

        // 5. Mark OTP as used
        await supabase
            .from('otp_codes')
            .update({ used: true })
            .eq('id', otpData.id);

        res.json({
            success: true,
            message: 'Registrasi berhasil'
        });

    } catch (err) {
        console.error('Register Error:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal registrasi server error'
        });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({ success: false, message: 'Identifier dan password wajib diisi' });
        }

        // Cari user
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`email.eq.${identifier},phone_number.eq.${identifier}`)
            .eq('is_verified', true)
            .maybeSingle(); // Gunakan maybeSingle agar tidak error jika null

        if (error || !user) {
            return res.status(401).json({ success: false, message: 'User tidak ditemukan' });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);

        if (!isValid) {
            return res.status(401).json({ success: false, message: 'Password salah' });
        }

        res.json({
            success: true,
            message: 'Login berhasil',
            user: {
                id: user.id,
                full_name: user.full_name,
                role: user.user_role
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Gagal login' });
    }
});

// Admin: Update User Profile
app.post('/admin/update-user', async (req, res) => {
    try {
        const { userId, full_name, phone_number, daily_rate } = req.body;
        if (!userId) return res.status(400).json({ success: false, message: 'User ID diperlukan' });

        const updateData = {};
        if (full_name) updateData.full_name = full_name;
        if (phone_number) updateData.phone_number = phone_number;
        if (daily_rate !== undefined) updateData.daily_rate = daily_rate;

        const { data, error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', userId)
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, message: 'Profil berhasil diperbarui', data });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Gagal update' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 OTP Server running on port ${PORT}`);
    console.log(`📧 Gmail: ${process.env.GMAIL_USER}`);
});