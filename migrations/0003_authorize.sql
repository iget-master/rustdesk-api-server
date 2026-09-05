-- Autorização das conexões pelo hbbs: com require_login, o hbbs só intermedeia conexões a
-- máquinas do grupo vindas de um cliente logado (token válido) com acesso ao grupo.
ALTER TABLE groups ADD COLUMN require_login INTEGER NOT NULL DEFAULT 0;

-- Conexões que o hbbs recusou depois de consultar a API.
CREATE TABLE authz_denied (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    peer_id   TEXT    NOT NULL,
    group_id  INTEGER,
    from_ip   TEXT    NOT NULL DEFAULT '',
    user_name TEXT    NOT NULL DEFAULT '',
    reason    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX authz_denied_at_idx ON authz_denied(at);
