-- IPv4 da máquina na rede local do grupo, enviado pelo cliente personalizado no heartbeat.
-- Vazio enquanto a máquina não reportar (cliente comum não manda esse campo).
ALTER TABLE devices ADD COLUMN lan_ip TEXT NOT NULL DEFAULT '';
