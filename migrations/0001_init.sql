-- Usuários que fazem login pela interface do cliente.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    display_name  TEXT    NOT NULL DEFAULT '',
    email         TEXT    NOT NULL DEFAULT '',
    note          TEXT    NOT NULL DEFAULT '',
    password_hash TEXT    NOT NULL,
    status        INTEGER NOT NULL DEFAULT 1,   -- 1 normal, 0 desabilitado
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);

-- Tokens Bearer emitidos por /api/login (um por cliente logado).
CREATE TABLE sessions (
    token        TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    TEXT    NOT NULL DEFAULT '',
    device_uuid  TEXT    NOT NULL DEFAULT '',
    device_os    TEXT    NOT NULL DEFAULT '',
    device_name  TEXT    NOT NULL DEFAULT '',
    device_type  TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- Address books: um pessoal por usuário (is_personal = 1) e quantos compartilhados quiser.
CREATE TABLE address_books (
    guid        TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_personal INTEGER NOT NULL DEFAULT 0,
    note        TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX address_books_personal_idx ON address_books(owner_id) WHERE is_personal = 1;
CREATE UNIQUE INDEX address_books_owner_name_idx ON address_books(owner_id, name);

-- Regra de acesso de outros usuários a um address book compartilhado
-- (1 leitura, 2 leitura/escrita, 3 controle total — mesmos valores do cliente).
CREATE TABLE address_book_shares (
    ab_guid TEXT    NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule    INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ab_guid, user_id)
);

CREATE TABLE ab_peers (
    ab_guid            TEXT    NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    id                 TEXT    NOT NULL,
    hash               TEXT    NOT NULL DEFAULT '',
    password           TEXT    NOT NULL DEFAULT '',
    username           TEXT    NOT NULL DEFAULT '',
    hostname           TEXT    NOT NULL DEFAULT '',
    platform           TEXT    NOT NULL DEFAULT '',
    alias              TEXT    NOT NULL DEFAULT '',
    tags               TEXT    NOT NULL DEFAULT '[]',  -- array JSON de nomes de tag
    force_always_relay INTEGER NOT NULL DEFAULT 0,
    rdp_port           TEXT    NOT NULL DEFAULT '',
    rdp_username       TEXT    NOT NULL DEFAULT '',
    login_name         TEXT    NOT NULL DEFAULT '',
    note               TEXT    NOT NULL DEFAULT '',
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    PRIMARY KEY (ab_guid, id)
);

CREATE TABLE ab_tags (
    ab_guid TEXT    NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    name    TEXT    NOT NULL,
    color   INTEGER NOT NULL DEFAULT 0,             -- ARGB como inteiro, igual ao cliente
    PRIMARY KEY (ab_guid, name)
);

-- Inventário alimentado por /api/heartbeat e /api/sysinfo.
CREATE TABLE devices (
    id            TEXT    PRIMARY KEY,               -- ID RustDesk
    uuid          TEXT    NOT NULL DEFAULT '',
    hostname      TEXT    NOT NULL DEFAULT '',
    username      TEXT    NOT NULL DEFAULT '',       -- usuário do SO
    os            TEXT    NOT NULL DEFAULT '',
    cpu           TEXT    NOT NULL DEFAULT '',
    memory        TEXT    NOT NULL DEFAULT '',
    version       TEXT    NOT NULL DEFAULT '',
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- usuário dono/atribuído
    device_group  TEXT    NOT NULL DEFAULT '',
    note          TEXT    NOT NULL DEFAULT '',
    conns         TEXT    NOT NULL DEFAULT '[]',     -- conn_ids ativos do último heartbeat
    sysinfo_json  TEXT    NOT NULL DEFAULT '{}',     -- último /api/sysinfo bruto
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL
);
CREATE INDEX devices_user_idx ON devices(user_id);

-- Auditoria de conexões (um registro por conn_id/session_id do lado controlado).
CREATE TABLE audit_conn (
    guid           TEXT    PRIMARY KEY,
    device_id      TEXT    NOT NULL,
    device_uuid    TEXT    NOT NULL DEFAULT '',
    conn_id        INTEGER NOT NULL,
    session_id     TEXT    NOT NULL,                 -- u64 no cliente; guardado como texto
    peer_id        TEXT    NOT NULL DEFAULT '',
    peer_name      TEXT    NOT NULL DEFAULT '',
    ip             TEXT    NOT NULL DEFAULT '',
    conn_type      INTEGER,
    primary_auth   INTEGER,
    two_factor     INTEGER,
    conn_audit_ref TEXT,
    note           TEXT    NOT NULL DEFAULT '',
    started_at     INTEGER NOT NULL,
    authed_at      INTEGER,
    closed_at      INTEGER
);
CREATE UNIQUE INDEX audit_conn_key_idx ON audit_conn(device_id, conn_id, session_id);
CREATE INDEX audit_conn_session_idx ON audit_conn(device_id, session_id);

CREATE TABLE audit_file (
    guid        TEXT    PRIMARY KEY,
    device_id   TEXT    NOT NULL,
    device_uuid TEXT    NOT NULL DEFAULT '',
    peer_id     TEXT    NOT NULL DEFAULT '',
    conn_id     INTEGER,
    type        INTEGER,                              -- 0 RemoteSend, 1 RemoteReceive
    path        TEXT    NOT NULL DEFAULT '',
    is_file     INTEGER NOT NULL DEFAULT 0,
    info        TEXT    NOT NULL DEFAULT '{}',        -- string JSON enviada pelo cliente
    created_at  INTEGER NOT NULL
);

CREATE TABLE audit_alarm (
    guid           TEXT    PRIMARY KEY,
    device_id      TEXT    NOT NULL,
    device_uuid    TEXT    NOT NULL DEFAULT '',
    typ            INTEGER,
    info           TEXT    NOT NULL DEFAULT '{}',
    conn_id        INTEGER,
    conn_audit_ref TEXT,
    created_at     INTEGER NOT NULL
);

-- Dedup das retentativas de auditoria (o cliente reenvia o mesmo nonce em erro/5xx).
CREATE TABLE audit_nonces (
    nonce      TEXT    PRIMARY KEY,
    created_at INTEGER NOT NULL
);
