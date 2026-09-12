-- Migration 0001: Initial schema
-- این فایل فقط یک بار اجرا می‌شود

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT UNIQUE NOT NULL,
    username TEXT,
    first_name TEXT,
    balance INTEGER DEFAULT 0,
    invited_by TEXT,
    referrals_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(telegram_id, wallet_address)
);

CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT NOT NULL,
    type TEXT NOT NULL,
    package_id TEXT NOT NULL,
    amount REAL NOT NULL,
    coins INTEGER NOT NULL,
    tx_hash TEXT,
    invoice_id TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id TEXT NOT NULL,
    referred_id TEXT UNIQUE NOT NULL,
    reward INTEGER DEFAULT 0,
    telegram_joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reward_claimed BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE referral_rewards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT NOT NULL,
    task TEXT NOT NULL,
    reward INTEGER NOT NULL,
    claimed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(telegram_id, task)
);

CREATE TABLE user_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    done_date DATE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(telegram_id, task_id, done_date)
);

CREATE TABLE processed_transactions (
    tx_hash TEXT PRIMARY KEY,
    telegram_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT,
    event_type TEXT,
    data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO config (key, value) VALUES 
    ('features', '{"stars":true,"ton":true,"referral":true,"tasks":true,"walletConnect":true,"ads":true}');

INSERT INTO config (key, value) VALUES 
    ('package_prices', '{"package_1":{"coins":10000,"usdt":1,"stars":100},"package_2":{"coins":80000,"usdt":5,"stars":500},"package_3":{"coins":200000,"usdt":10,"stars":1000},"package_4":{"coins":1000000,"usdt":50,"stars":5000},"package_5":{"coins":3000000,"usdt":100,"stars":10000}}');