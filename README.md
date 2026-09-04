# rustdesk-api-server

Servidor de API mínimo, em **Rust + SQLite**, que implementa o que o cliente RustDesk pede por HTTP:
login, address book (pessoal e compartilhado), aba **Grupo**, inventário via heartbeat/sysinfo e
auditoria de conexões. É o papel que o *RustDesk Server Pro* cumpre — o `rustdesk-server`
open-source (hbbs/hbbr) **não** implementa nenhum desses endpoints, e este projeto **não substitui
o hbbs/hbbr**: ele roda ao lado deles.

O contrato implementado foi levantado direto do código do cliente; veja
[`docs/rustdesk-api-endpoints.md`](docs/rustdesk-api-endpoints.md).

## O que funciona

| Área | Endpoints | Comportamento |
|---|---|---|
| Conta | `GET /api/login-options`, `POST /api/login`, `POST /api/currentUser`, `POST /api/logout` | usuário + senha (argon2); token Bearer opaco guardado em `sessions`; sem OIDC/2FA (`login-options` devolve `[]`) |
| Address book | `POST /api/ab/personal`, `ab/settings`, `ab/shared/profiles`, `ab/peers`, `ab/tags/{guid}` e as mutações `peer/add`, `peer/update`, `peer/{guid}` (DELETE), `tag/add`, `tag/rename`, `tag/update`, `tag/{guid}` (DELETE) | formato atual (vários ABs); AB pessoal criado no primeiro acesso; compartilhados criados pela CLI com regra leitura / leitura-escrita / controle total |
| Aba Grupo | `GET /api/users`, `GET /api/peers`, `GET /api/device-group/accessible` | todos os usuários ativos veem todos os dispositivos (instalação de um inquilino); dono e grupo vêm da atribuição (`preset-*`, `--assign` ou CLI) |
| Dispositivos | `POST /api/heartbeat`, `POST /api/sysinfo` | inventário (host, usuário do SO, SO, CPU, memória, versão); responde `{"sysinfo": true}` quando ainda não conhece o ID; aplica os campos `preset-*` de instalações pré-configuradas |
| Auditoria | `POST /api/audit/conn`, `audit/file`, `audit/alarm`, `GET /api/audit/conn/active`, `PUT /api/audit` | registros por conexão, arquivos e alarmes; dedup por `nonce`; notas de fim de sessão |
| Provisionamento | `POST /api/devices/cli` (`rustdesk --assign`), `POST /api/devices/deploy` | `--assign` com token de admin atribui usuário/grupo/AB; `deploy` responde `NOT_ENABLED` (o hbbs OSS não exige deploy) |
| Outros | `POST /api/switch-grant` | aceito sem verificação (sem a chave do dispositivo, que fica no hbbs, não há como validar; é inerte com o hbbs OSS) |

Tudo o que não está na tabela responde **404** — o cliente foi escrito para conviver com isso
(OIDC, address book legado `/api/ab`, `/api/ab/get`, upload de gravação).

## Subindo em produção (Docker)

Pré-requisito: um `rustdesk-server` (hbbs/hbbr) já no ar. O container só precisa da porta
**21114/tcp** aberta — é a porta que o cliente deduz a partir do *ID server* (21116 − 2).

```bash
# no servidor, dentro da pasta server/
export RUSTDESK_API_ADMIN_PASSWORD='uma-senha-forte'   # usada só na 1ª subida
docker compose up -d --build
docker compose logs -f
```

O banco fica em `./data/rustdesk-api.db` (volume). Na primeira subida, com o banco vazio, o
usuário `admin` é criado com a senha da variável. Depois disso a variável é ignorada — use a CLI:

```bash
docker exec -it rustdesk-api rustdesk-api user add alice            # imprime uma senha gerada
docker exec -it rustdesk-api rustdesk-api user add bob --password 'x' --admin
docker exec -it rustdesk-api rustdesk-api user list
```

Para rodar o container com outro usuário (não-root), use `user: "1000:1000"` no compose e faça
`chown -R 1000:1000 data/` antes.

### HTTPS

O cliente aceita HTTP puro. Se quiser HTTPS, coloque um proxy reverso (Caddy, nginx, Traefik) na
frente e configure `https://api.exemplo.com` nos clientes. Use certificado **válido**: o caminho
Rust do cliente tolera auto-assinado, mas a interface Flutter (login, address book) não.

## Configurando os clientes

Configurações → Rede → *ID/Relay server*:

- **ID server**: `rd.exemplo.com` (o que você já usa)
- **API server**: `http://rd.exemplo.com:21114` — pode ficar vazio se a API estiver no mesmo host
  do ID server, na porta 21114; o cliente deduz sozinho.

Aparece o botão **Login** na aba de address book. Após o login, as abas *Address book* e *Grupo*
passam a usar este servidor. Dispositivos com o serviço instalado começam a mandar heartbeat e
inventário sozinhos (sem login) e aparecem em `rustdesk-api device list` e na aba Grupo.

## CLI

O binário é ao mesmo tempo o servidor e a ferramenta de administração. Dentro do container:
`docker exec -it rustdesk-api rustdesk-api <comando>`.

```text
rustdesk-api serve [--bind 0.0.0.0:21114]        # padrão sem subcomando
rustdesk-api user add <nome> [--password S] [--admin] [--display-name N] [--email E]
rustdesk-api user passwd <nome> [--password S]  # encerra as sessões
rustdesk-api user list | enable <nome> | disable <nome> | delete <nome>
rustdesk-api ab create <nome> --owner <usuário>
rustdesk-api ab share <nome> --owner <dono> --user <usuário> --rule read|rw|full
rustdesk-api ab unshare <nome> --owner <dono> --user <usuário>
rustdesk-api ab list
rustdesk-api device list
rustdesk-api device assign <id> [--user U] [--group G] [--note N]
rustdesk-api device delete <id>
rustdesk-api token <usuário>                     # token Bearer p/ scripts e `rustdesk --assign`
rustdesk-api health                              # usado no HEALTHCHECK
```

Atribuir um dispositivo a partir dele mesmo (requer token de um usuário **admin**):

```bash
rustdesk --assign --token <token> --user_name alice --device_group_name TI --address_book_name Suporte
```

Instalações pré-configuradas (opções `preset-user-name`, `preset-device-group-name`,
`preset-address-book-name`, `preset-address-book-tag`, ...) são aplicadas automaticamente quando o
dispositivo envia o `sysinfo`: o dono só é definido se ainda não houver um, e o peer só entra no
address book se ainda não estiver lá — edições feitas pela interface não são sobrescritas.

## Variáveis de ambiente

| Variável | Padrão | Uso |
|---|---|---|
| `RUSTDESK_API_DB_PATH` | `rustdesk-api.db` (`/data/rustdesk-api.db` no container) | arquivo SQLite (WAL) |
| `RUSTDESK_API_BIND` | `0.0.0.0:21114` | endereço de escuta |
| `RUSTDESK_API_ADMIN_USER` / `RUSTDESK_API_ADMIN_PASSWORD` | `admin` / — | criam o primeiro usuário quando o banco está vazio |
| `RUST_LOG` | `info,sqlx=warn` | nível de log (`debug` mostra cada requisição) |

## Modelo de permissões

- Todo usuário ativo vê todos os usuários e dispositivos (`/api/users`, `/api/peers`).
- Address book pessoal: só o dono. Compartilhado: dono = controle total; os demais conforme
  `ab share --rule` (leitura só lista; `rw`/`full` também alteram peers e tags).
- `is_admin` é exigido apenas em `POST /api/devices/cli` (`rustdesk --assign`).
- Senhas com argon2id; tokens de 256 bits, revogados em `logout`, `user passwd`, `user disable`.

## Desenvolvimento

```bash
cargo build                                   # precisa de gcc (sqlite embutido)
RUSTDESK_API_DB_PATH=/tmp/dev.db cargo run -- user add admin --password admin --admin
RUSTDESK_API_DB_PATH=/tmp/dev.db cargo run -- serve --bind 127.0.0.1:21114
RD_PASS=admin ./scripts/smoke-test.sh          # exercita o contrato inteiro com curl
```

Backup: copie `rustdesk-api.db` com o serviço parado, ou use
`sqlite3 rustdesk-api.db ".backup backup.db"` com ele rodando.

Testando o container **dentro do WSL** com o projeto em `/mnt/c/...`: não use o bind mount
`./data` (SQLite sobre drvfs/9p trava); suba com um volume nomeado:

```bash
docker build -t rustdesk-api-server:local .
docker run -d --name rustdesk-api -p 21114:21114 -v rustdesk-api-data:/data \
  -e RUSTDESK_API_ADMIN_PASSWORD='admin123' rustdesk-api-server:local
```

No Windows, o cliente RustDesk enxerga esse container em `http://127.0.0.1:21114`
(o WSL encaminha `localhost`).

## Limitações conhecidas

- Sem OIDC, 2FA de login, verificação por e-mail, address book legado ou console web.
- O heartbeat ainda não devolve `strategy` nem `disconnect` (a estrutura está pronta para isso).
- O status online da aba Grupo vem do hbbs, não desta API; `device list` mostra online pelo
  heartbeat (45 s).
- Um só inquilino: não há isolamento entre equipes de usuários.
