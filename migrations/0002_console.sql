-- Grupos (grupos de dispositivos administrados pelo console).
CREATE TABLE groups (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT    NOT NULL UNIQUE,
    password           TEXT    NOT NULL DEFAULT '',   -- senha permanente única do grupo; vai para o AB compartilhado
    ab_guid            TEXT    REFERENCES address_books(guid) ON DELETE SET NULL,
    options            TEXT    NOT NULL DEFAULT '{}', -- config_options empurradas aos clientes via heartbeat (strategy)
    options_updated_at INTEGER NOT NULL DEFAULT 0,
    note               TEXT    NOT NULL DEFAULT '',
    enroll_token       TEXT    NOT NULL DEFAULT '',   -- segredo do script de instalação (POST /api/enroll)
    created_at         INTEGER NOT NULL
);
CREATE UNIQUE INDEX groups_enroll_token_idx ON groups(enroll_token) WHERE enroll_token <> '';

ALTER TABLE devices ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
CREATE INDEX devices_group_idx ON devices(group_id);

-- staff: vê toda a frota na aba Grupo; external: só os grupos a que tem acesso.
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'staff';
ALTER TABLE users ADD COLUMN expires_at INTEGER;             -- NULL = sem validade

ALTER TABLE address_book_shares ADD COLUMN expires_at INTEGER; -- NULL = sem validade

-- Segundo fator do login: 'console' = exige um código de acesso emitido pelo console.
ALTER TABLE users ADD COLUMN tfa TEXT NOT NULL DEFAULT 'none';
-- Validade das sessões criadas no login, em horas (0 = sem validade).
ALTER TABLE users ADD COLUMN session_hours INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN expires_at INTEGER;             -- NULL = sem validade

-- Códigos de acesso de uso único emitidos pelo console.
CREATE TABLE access_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code       TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_by INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX access_codes_user_idx ON access_codes(user_id, code);

-- Etapa 1 do login aprovada e aguardando o código: o `secret` que o cliente devolve na etapa 2.
CREATE TABLE login_challenges (
    secret     TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Configuração do console (servidor de ID, chave, URL da API, link do instalador).
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
