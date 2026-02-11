-- ============================================
-- Full Database Schema for Material Store App
-- Run this in Supabase SQL Editor to fix "missing table" errors
-- ============================================

-- 1. USERS Table
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    phone_number TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    user_role TEXT[] DEFAULT '{}', -- Array of roles, e.g. ['buyer'], ['owner'], ['worker']
    
    -- Location & Worker specific fields
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    is_working BOOLEAN DEFAULT FALSE,
    daily_rate NUMERIC,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RLS for users
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Allow Anon to insert (Register)
CREATE POLICY "Allow public insert users" ON public.users FOR INSERT WITH CHECK (true);
-- Allow Anon to select (Login check)
CREATE POLICY "Allow public select users" ON public.users FOR SELECT USING (true);
-- Allow users to update their own data (optional, simplified for now to allow all)
CREATE POLICY "Allow public update users" ON public.users FOR UPDATE USING (true);


-- 2. WORKER INFO Table
CREATE TABLE IF NOT EXISTS public.worker_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    address TEXT,
    ktp_url TEXT,
    account_status TEXT DEFAULT 'pending', -- 'pending', 'verified', 'rejected'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

ALTER TABLE public.worker_info ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public all worker_info" ON public.worker_info FOR ALL USING (true);


-- 3. WORKER SKILLS Table
CREATE TABLE IF NOT EXISTS public.worker_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id UUID REFERENCES public.worker_info(id) ON DELETE CASCADE,
    skill_name TEXT NOT NULL,
    certificate_url TEXT,
    verification_status TEXT DEFAULT 'pending', -- 'pending', 'verified', 'rejected'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE public.worker_skills ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public all worker_skills" ON public.worker_skills FOR ALL USING (true);

-- 4. OTP CODES Table (If not already created)
CREATE TABLE IF NOT EXISTS public.otp_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE public.otp_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public all otp_codes" ON public.otp_codes FOR ALL USING (true);
