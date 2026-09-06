-- Cliente personalizado (RustdeskOlirio): a senha permanente do grupo é entregue no heartbeat.
ALTER TABLE devices ADD COLUMN sync_client INTEGER NOT NULL DEFAULT 0;     -- 1 = manda enroll_token/password_tag
ALTER TABLE devices ADD COLUMN password_synced INTEGER NOT NULL DEFAULT 0; -- 1 = último heartbeat confirmou a senha do grupo
ALTER TABLE devices ADD COLUMN password_synced_at INTEGER;
