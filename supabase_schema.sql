-- Anchor Project - Supabase SQL Schema
-- Run this in your Supabase SQL editor

-- Sessions table: Stores the hardware-anchored session records
CREATE TABLE IF NOT EXISTS anchor_sessions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Threats table: Watcher logs suspicious hijacking attempts here
CREATE TABLE IF NOT EXISTS anchor_threats (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    token TEXT NOT NULL,
    reason TEXT NOT NULL,
    ip_address TEXT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Events table: Audit trail for session lifecycle (creation, validation, termination)
CREATE TABLE IF NOT EXISTS anchor_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    token TEXT NOT NULL,
    event TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
