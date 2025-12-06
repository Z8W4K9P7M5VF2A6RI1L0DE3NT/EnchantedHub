CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE,
  username TEXT,
  password_hash TEXT,
  discord_id TEXT UNIQUE,
  discord_avatar TEXT,
  role TEXT DEFAULT 'user',
  refresh_token TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scripts (
  key VARCHAR(64) PRIMARY KEY,
  script TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  uses INTEGER DEFAULT 0,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  title TEXT
);

CREATE TABLE IF NOT EXISTS alu_logs (
  id SERIAL PRIMARY KEY,
  script_key VARCHAR(64),
  user_id INTEGER,
  event_type TEXT,
  ip TEXT,
  user_agent TEXT,
  extra JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
