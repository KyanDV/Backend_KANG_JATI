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

// Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

// Supabase Admin client (for Auth management)
// Requires SERVICE_ROLE_KEY to create users
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

// Gmail SMTP transporter with explicit settings
// Gmail SMTP transporter with explicit settings
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // Use TLS
    requireTLS: true,
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
});

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

        // Generate OTP and expiry (5 minutes from now)
        // Check for existing active OTP created recently (spam click prevention)
        const { data: existingOTP } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('used', false)
            .gte('created_at', new Date(Date.now() - 60 * 1000).toISOString()) // Created within last 60s
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        let otp;
        let expiresAt;

        if (existingOTP) {
            console.log(`Resending EXISTING OTP to ${email} (Anti-Spam)`);
            otp = existingOTP.code;
            // No need to insert new DB record
        } else {
            // Generate NEW OTP
            otp = generateOTP();
            expiresAt = new Date(Date.now() + 5 * 60 * 1000);

            // Invalidate OLD OTPs
            await supabase
                .from('otp_codes')
                .update({ used: true })
                .eq('email', email)
                .eq('used', false);

            // Store NEW OTP
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

        // Send email
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
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 12px;">
            Jika Anda tidak meminta kode ini, abaikan email ini.
          </p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);

        console.log(`OTP sent to ${email}`);
        res.json({ success: true, message: 'Kode OTP telah dikirim ke email Anda' });

    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).json({ success: false, message: 'Gagal mengirim OTP: ' + error.message });
    }
});

// Verify OTP endpoint
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'Email dan OTP diperlukan' });
        }

        // Find valid OTP
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
            console.log(`Verify Failed for ${email}. Input: ${otp}`);
            // Cek apakah ada OTP lain yang valid tapi beda kode (kasus spam klik)
            const { data: latestOTP } = await supabase
                .from('otp_codes')
                .select('*')
                .eq('email', email)
                .order('created_at', { ascending: false })
                .limit(1)
                .single();

            if (latestOTP) {
                console.log(`Latest Valid OTP in DB: ${latestOTP.code} (Status: ${latestOTP.used ? 'Used' : 'Active'})`);
            }

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

        console.log(`OTP verified for ${email}`);
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
            console.log('Register Error: Missing fields', req.body);
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
            console.log(`[Register] OTP Verify Failed for ${email}. Input: ${otp}`);

            // Debug: Check what IS in the DB
            const { data: dbOtps } = await supabase
                .from('otp_codes')
                .select('*')
                .eq('email', email)
                .order('created_at', { ascending: false })
                .limit(3);

            console.log('Recent OTPs in DB:', dbOtps);

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
            email_confirm: true // Auto confirm since we verified OTP
        });

        if (authError) {
            // Check if user already exists (Zombie User scenario)
            if (authError.message.includes('already registered') || authError.status === 422) {
                console.log('User already in Auth, checking public.users...');

                // 1. Check if it's a REAL duplicate (already in public DB)
                const { data: existingPublicUser } = await supabase
                    .from('users')
                    .select('id')
                    .eq('email', email)
                    .maybeSingle();

                if (existingPublicUser) {
                    return res.status(400).json({ success: false, message: 'Email sudah terdaftar sepenuhnya.' });
                }

                // 2. It's a Zombie (Auth exists, Public missing). Try to recover ID via Login.
                // We use signInWithPassword to prove ownership (re-using the password they just sent)
                const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({
                    email: email,
                    password: password
                });

                if (loginError || !loginData.user) {
                    console.error('Zombie recovery failed:', loginError);
                    return res.status(400).json({
                        success: false,
                        message: 'Email sudah terdaftar. Password mungkin salah atau akun terkunci.'
                    });
                }

                console.log('Zombie Recovered! ID:', loginData.user.id);
                userId = loginData.user.id; // Use existing ID
            } else {
                console.error('Auth Error:', authError);
                return res.status(400).json({
                    success: false,
                    message: 'Gagal membuat akun Auth: ' + authError.message
                });
            }
        } else {
            userId = authData.user.id;
        }

        // 3. Hash password (still kept for public.users legacy)
        const passwordHash = await bcrypt.hash(password, 12);

        // 4. Create User in public.users with SYNCED ID
        const { error: userError } = await supabase
            .from('users')
            .insert({
                id: userId, // Gunakan ID dari Auth
                email,
                phone_number,
                full_name,
                password_hash: passwordHash,
                is_verified: true,
                user_role: [role],
            });

        if (userError) {
            // Rollback: Delete Auth user if public insert fails
            await supabaseAdmin.auth.admin.deleteUser(userId);

            // Check for duplicate key error (email or phone)
            if (userError.code === '23505') {
                console.log('Register Error: Duplicate User', userError.message);
                return res.status(400).json({
                    success: false,
                    message: 'Email atau Nomor HP sudah terdaftar di database publik'
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
        console.error(err);
        res.status(500).json({
            success: false,
            message: 'Gagal registrasi: ' + err.message
        });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;

        if (!identifier || !password) {
            return res.status(400).json({
                success: false,
                message: 'Identifier dan password wajib diisi'
            });
        }

        // cari user by email atau phone
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`email.eq.${identifier},phone_number.eq.${identifier}`)
            .eq('is_verified', true)
            .single();

        if (error || !user) {
            return res.status(401).json({
                success: false,
                message: 'User tidak ditemukan'
            });
        }

        // compare password
        const isValid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Password salah'
            });
        }

        // TODO: generate JWT
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
        res.status(500).json({
            success: false,
            message: 'Gagal login'
        });
    }
});


// Admin: Update User Profile
app.post('/admin/update-user', async (req, res) => {
    try {
        const { userId, full_name, phone_number, daily_rate } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false, message: 'User ID diperlukan' });
        }

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

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Profil berhasil diperbarui',
            data
        });

    } catch (err) {
        console.error('Error update user:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal memperbarui profil: ' + err.message
        });
    }
});

// Admin: Reset Password
app.post('/admin/reset-password', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false, message: 'User ID diperlukan' });
        }

        // Hash default password '12345678'
        const passwordHash = await bcrypt.hash('12345678', 12);

        const { data, error } = await supabase
            .from('users')
            .update({ password_hash: passwordHash })
            .eq('id', userId)
            .select()
            .single();

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Password berhasil direset ke 12345678'
        });

    } catch (err) {
        console.error('Error reset password:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal reset password: ' + err.message
        });
    }
});

// Admin: Delete User
app.post('/admin/delete-user', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false, message: 'User ID diperlukan' });
        }

        const { error } = await supabase
            .from('users')
            .delete()
            .eq('id', userId);

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'User berhasil dihapus'
        });

    } catch (err) {
        console.error('Error delete user:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal menghapus user: ' + err.message
        });
    }
});

// User: Change Password
app.post('/change-password', async (req, res) => {
    try {
        const { userId, oldPassword, newPassword } = req.body;

        if (!userId || !oldPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Data tidak lengkap' });
        }

        // 1. Get user to verify old password
        const { data: user, error: fetchError } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', userId)
            .single();

        if (fetchError || !user) {
            return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
        }

        // 2. Verify Old Password
        const match = await bcrypt.compare(oldPassword, user.password_hash);
        if (!match) {
            return res.status(400).json({ success: false, message: 'Password lama salah' });
        }

        // 3. Hash New Password
        const newPasswordHash = await bcrypt.hash(newPassword, 12);

        // 4. Update Password
        const { error: updateError } = await supabase
            .from('users')
            .update({ password_hash: newPasswordHash })
            .eq('id', userId);

        if (updateError) {
            throw updateError;
        }

        res.json({
            success: true,
            message: 'Password berhasil diubah'
        });

    } catch (err) {
        console.error('Error change password:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal mengubah password: ' + err.message
        });
    }
});

app.post('/change-profile', async (req, res) => {
    try {
        const { userId, fullName, phoneNumber } = req.body;

        if (!userId || !fullName || !phoneNumber) {
            return res.status(400).json({ success: false, message: 'Data tidak lengkap' });
        }


        const { error: updateError } = await supabase
            .from('users')
            .update({
                'full_name': fullName,
                'phone_number': phoneNumber,
            })
            .eq('id', userId);

        if (updateError) {
            throw updateError;
        }

        res.json({
            success: true,
            message: 'Profil berhasil diubah'
        });
    } catch (err) {
        console.error('Error change profile:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal mengubah profil: ' + err.message,
        })
    }
});

app.post('/change-location', async (req, res) => {
    try {
        const { userId, latitude, longitude, isWorking } = req.body;

        if (!userId || !latitude || !longitude) {
            return res.status(400).json({ success: false, message: 'Data tidak lengkap' });
        }

        console.log(isWorking);
        if (isWorking !== null) {
            const { error: updateError } = await supabase
                .from('users')
                .update({
                    'is_working': isWorking,
                    'latitude': latitude,
                    'longitude': longitude,
                })
                .eq('id', userId);

            if (updateError) {
                throw updateError;
            }
        } else {
            const { error: updateError } = await supabase
                .from('users')
                .update({
                    'latitude': latitude,
                    'longitude': longitude,
                })
                .eq('id', userId);

            if (updateError) {
                throw updateError;
            }
        }

        res.json({
            success: true,
            message: 'Lokasi berhasil diubah'
        });
    } catch (err) {
        console.error('Error change location:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal mengubah lokasi: ' + err.message,
        })
    }
});

// Worker: Add Skill
app.post('/worker/add-skill', async (req, res) => {
    try {
        const { userId, skillName, certificateUrl } = req.body;

        if (!userId || !skillName || !certificateUrl) {
            return res.status(400).json({ success: false, message: 'Data tidak lengkap' });
        }

        // 1. Ensure worker_info exists
        const { data: workerInfo, error: infoError } = await supabase
            .from('worker_info')
            .select('id')
            .eq('user_id', userId)
            .maybeSingle();

        if (infoError) throw infoError;

        let workerId;
        if (!workerInfo) {
            const { data: newWorker, error: createError } = await supabase
                .from('worker_info')
                .insert({ user_id: userId })
                .select()
                .single();
            if (createError) throw createError;
            workerId = newWorker.id;
        } else {
            workerId = workerInfo.id;
        }

        // 2. Insert Skill
        const { error: skillError } = await supabase
            .from('worker_skills')
            .insert({
                worker_id: workerId,
                skill_name: skillName,
                certificate_url: certificateUrl,
                verification_status: 'pending'
            });

        if (skillError) throw skillError;

        res.json({
            success: true,
            message: 'Keahlian berhasil ditambahkan dan menunggu verifikasi'
        });

    } catch (err) {
        console.error('Error add skill:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal menambahkan keahlian: ' + err.message,
        })
    }
});

// Admin: Verify Skill
app.post('/admin/verify-skill', async (req, res) => {
    try {
        const { skillId, status } = req.body;

        if (!skillId || !['verified', 'rejected', 'pending'].includes(status)) {
            return res.status(400).json({ success: false, message: 'Data invalid' });
        }

        const { error } = await supabase
            .from('worker_skills')
            .update({ verification_status: status })
            .eq('id', skillId);

        if (error) throw error;

        res.json({
            success: true,
            message: `Status keahlian diubah menjadi ${status}`
        });

    } catch (err) {
        console.error('Error verify skill:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal verifikasi: ' + err.message,
        })
    }
});

// Worker: Initial Verification (KTP + First Skill)
app.post('/worker/submit-initial', async (req, res) => {
    try {
        const { userId, ktpUrl, address, skillName, certificateUrl } = req.body;

        if (!userId || !ktpUrl || !address || !skillName || !certificateUrl) {
            return res.status(400).json({ success: false, message: 'Data tidak lengkap' });
        }

        // 1. Upsert worker_info (Update Account Status & KTP)
        const { data: workerInfo, error: infoError } = await supabase
            .from('worker_info')
            .upsert({
                user_id: userId,
                address: address,
                ktp_url: ktpUrl,
                account_status: 'pending' // Set directly to pending
            }, { onConflict: 'user_id' })
            .select()
            .single();

        if (infoError) throw infoError;

        // 2. Insert First Skill
        const { error: skillError } = await supabase
            .from('worker_skills')
            .insert({
                worker_id: workerInfo.id,
                skill_name: skillName,
                certificate_url: certificateUrl,
                verification_status: 'pending'
            });

        if (skillError) throw skillError;

        res.json({
            success: true,
            message: 'Verifikasi berhasil dikirim. Mohon tunggu persetujuan admin.'
        });

    } catch (err) {
        console.error('Error submit initial:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal mengirim data: ' + err.message,
        })
    }
});

// Admin: Verify Account (Unified - Account + All Pending Skills)
app.post('/admin/verify-account', async (req, res) => {
    try {
        const { userId, status } = req.body;

        if (!userId || !['verified', 'rejected'].includes(status)) {
            return res.status(400).json({ success: false, message: 'Data invalid' });
        }

        // 1. Update Worker Info
        const { data: workerInfo, error: infoError } = await supabase
            .from('worker_info')
            .update({ account_status: status })
            .eq('user_id', userId)
            .select()
            .single();

        if (infoError) throw infoError;

        // 2. Update ALL Pending Skills for this worker
        // This fulfills the "One Click" requirement
        const { error: skillError } = await supabase
            .from('worker_skills')
            .update({ verification_status: status })
            .eq('worker_id', workerInfo.id)
            .eq('verification_status', 'pending'); // Only update pending ones

        if (skillError) throw skillError;

        res.json({
            success: true,
            message: `Akun dan keahlian berhasil di-${status}`
        });

    } catch (err) {
        console.error('Error verify account:', err);
        res.status(500).json({
            success: false,
            message: 'Gagal verifikasi: ' + err.message,
        })
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 OTP Server running on port ${PORT}`);
    console.log(`📧 Gmail: ${process.env.GMAIL_USER}`);
    console.log(`🔗 Supabase: ${process.env.SUPABASE_URL}`);
});
