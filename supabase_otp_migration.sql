-- ============================================
-- OTP Codes Table for Email OTP System
-- Run this in Supabase SQL Editor
-- ============================================

-- Create otp_codes table
CREATE TABLE IF NOT EXISTS otp_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_otp_codes_email ON otp_codes(email);
CREATE INDEX IF NOT EXISTS idx_otp_codes_lookup ON otp_codes(email, code, used);

-- Enable Row Level Security (RLS)
ALTER TABLE otp_codes ENABLE ROW LEVEL SECURITY;

-- Policy: Allow insert from service role (NodeJS backend)
CREATE POLICY "Allow service insert" ON otp_codes
  FOR INSERT
  WITH CHECK (true);

-- Policy: Allow update from service role
CREATE POLICY "Allow service update" ON otp_codes
  FOR UPDATE
  USING (true);

-- Policy: Allow select from service role  
CREATE POLICY "Allow service select" ON otp_codes
  FOR SELECT
  USING (true);

-- Optional: Auto-delete expired OTPs (run periodically or as cron job)
-- DELETE FROM otp_codes WHERE expires_at < NOW() OR used = TRUE;
