# rustdesk-api-server

Servidor de API + **console web** para uma rede de máquinas RustDesk auto-hospedada, em
**Rust + SQLite**, num único binário e num único container. Implementa o que o cliente RustDesk
pede por HTTP (login, address book, aba Grupo, inventário via heartbeat/sysinfo, auditoria) — o
papel que o *RustDesk Server Pro* cumpre — e, por cima disso, um console para organizar as máquinas
em **grupos**, dar acesso direto à equipe e acesso sob demanda a terceiros.

Roda ao lado do `rustdesk-server` (hbbs/hbbr) e **não o substitui**. Para usar chave no hbbs junto
com login de conta, é preciso o hbbs deste fork:
[iget-master/rustdesk-server](https://github.com/iget-master/rustdesk-server) (o OSS original não
implementa o handshake `secure_tcp` que o cliente exige nessa combinação).

O contrato do cliente está em [`docs/rustdesk-api-endpoints.md`](docs/rustdesk-api-endpoints.md).

## O que resolve

| Objetivo | Como |
|---|---|
| Agrupar as máquinas por unidade (posto, loja, filial…) | **Grupos**: cada grupo tem um script de instalação que configura o RustDesk, grava a senha permanente do grupo e matricula a máquina nele (`/api/enroll`). O grupo aparece com esse nome na aba *Grupo* dos clientes. |
| Equipe de TI entrar direto, sem senha e sem pedir permissão | O grupo tem **uma senha permanente única**, gravada nas máquinas e guardada no **address book compartilhado do grupo**, mantido pelo console. Administradores e quem tem acesso ao grupo conectam com um clique: o cliente usa a senha do address book e as máquinas ficam em `approve-mode=password`, empurrado pelo heartbeat. |
| Terceiro (suporte do ERP/PDV) com acesso limitado e temporário | Usuário **externo** com acesso só ao grupo (somente leitura), **código de acesso** emitido no console na hora do login (uso único, validade em minutos) e **sessão que expira** em X horas. Vencida, o cliente dele perde o address book. |

## Subindo em produção (Docker)

```bash
git clone https://github.com/iget-master/rustdesk-api-server.git && cd rustdesk-api-server
RUSTDESK_API_ADMIN_PASSWORD='uma-senha-forte' docker compose up -d --build
```

- Porta **21114/tcp** aberta para as máquinas e para quem usa o console.
- Banco em `./data/rustdesk-api.db` (volume). Na primeira subida cria o usuário `admin` com a
  senha da variável; depois ela é ignorada.
- **Atualizar**: `git pull && docker compose up -d --build`. As migrações rodam sozinhas no start.

Console: `http://SEU-SERVIDOR:21114/` (entre com `admin`). HTTPS opcional via proxy reverso com
certificado válido — a interface Flutter do cliente não aceita auto-assinado.

## Primeiros passos no console

1. **Configurações** — servidor de ID (host do hbbs), chave pública (`Key`), URL da API e o link
   do instalador do RustDesk. Só servem para gerar os scripts de instalação.
2. **Grupos → Novo grupo** — o console gera a senha permanente do grupo, o address book
   compartilhado e o token de matrícula.
3. **Script de instalação** (por grupo) — rode como administrador em cada máquina. Ele instala o
   RustDesk se preciso, aponta para o seu servidor, grava a senha do grupo, deixa
   `approve-mode=password` / `verification-method=use-permanent-password` e matricula a máquina.
   Máquinas que já têm o serviço apontando para esta API aparecem sozinhas em **Dispositivos**
   (sem grupo) e podem ser movidas para o grupo — mas a senha permanente só entra via script ou
   `rustdesk --password`.
4. **Usuários** — a equipe é `Equipe` (vê toda a frota); administradores têm controle total de
   todos os grupos e usam o console. Terceiros são `Externo`: só enxergam os grupos concedidos em
   **Acessos**.
5. **Acesso sob demanda** (para terceiros): em *Usuários*, ative "Exigir código de acesso" e defina
   a validade da sessão (ex.: 4 h). Quando o técnico for entrar: *Gerar código* → passe o código a
   ele. No cliente RustDesk ele faz login com usuário e senha, o RustDesk pede o código, e pronto.
   *Derrubar sessões* encerra o acesso na hora.

Nos clientes, o campo *API Server* é `http://SEU-SERVIDOR:21114` (ou vazio, se a API está no host
do ID server na porta padrão). O botão **Entrar** fica na aba de address book.

## O que a API implementa

| Área | Endpoints | Comportamento |
|---|---|---|
| Conta | `GET /api/login-options`, `POST /api/login`, `POST /api/currentUser`, `POST /api/logout` | usuário + senha (argon2); segundo fator opcional por código do console (fluxo `tfa_check` do cliente); sessões com validade opcional |
| Address book | `POST /api/ab/personal`, `ab/settings`, `ab/shared/profiles`, `ab/peers`, `ab/tags/{guid}` e as mutações de peer/tag | formato atual; AB pessoal automático; ABs dos grupos mantidos pelo console; regra leitura / leitura-escrita / controle total com validade |
| Aba Grupo | `GET /api/users`, `GET /api/peers`, `GET /api/device-group/accessible` | equipe vê tudo; externos só os seus grupos |
| Dispositivos | `POST /api/heartbeat`, `POST /api/sysinfo`, `POST /api/enroll` | inventário; `strategy` com as opções do grupo quando mudam; presets `preset-*`; matrícula por token do grupo |
| Auditoria | `POST /api/audit/conn`, `audit/file`, `audit/alarm`, `GET /api/audit/conn/active`, `PUT /api/audit` | conexões, arquivos, alarmes, notas; dedup por `nonce` |
| Provisionamento | `POST /api/devices/cli` (`rustdesk --assign`, exige admin), `POST /api/devices/deploy` (`NOT_ENABLED`) | `--device_group_name` vira grupo |
| Console | `/admin/api/*` (só admin), interface em `/` | grupos, dispositivos, usuários, acessos, códigos, auditoria, configurações |

O que não está aí responde 404 (OIDC, address book legado, gravação).

## CLI

Dentro do container: `docker exec -it rustdesk-api rustdesk-api <comando>`.

```text
rustdesk-api serve [--bind 0.0.0.0:21114]
rustdesk-api user add <nome> [--password S] [--admin] [--display-name N] [--email E]
rustdesk-api user passwd <nome> [--password S] | list | enable <nome> | disable <nome> | delete <nome>
rustdesk-api ab create <nome> --owner <usuário> | share <nome> --owner <dono> --user <u> --rule read|rw|full | unshare … | list
rustdesk-api device list | assign <id> [--user U] [--group GRUPO] [--note N] | delete <id>
rustdesk-api token <usuário>          # token Bearer para scripts / `rustdesk --assign`
rustdesk-api health
```

## Variáveis de ambiente

| Variável | Padrão | Uso |
|---|---|---|
| `RUSTDESK_API_DB_PATH` | `rustdesk-api.db` (`/data/rustdesk-api.db` no container) | arquivo SQLite (WAL) |
| `RUSTDESK_API_BIND` | `0.0.0.0:21114` | endereço de escuta |
| `RUSTDESK_API_ADMIN_USER` / `RUSTDESK_API_ADMIN_PASSWORD` | `admin` / — | primeiro usuário, só com o banco vazio |
| `RUST_LOG` | `info,sqlx=warn` | nível de log |

## Modelo de permissões

- **Administrador**: console, controle total de todos os grupos, `rustdesk --assign`.
- **Equipe**: vê toda a frota na aba Grupo; nos address books, o que lhe for concedido.
- **Externo**: só os grupos concedidos, sem lista de usuários, sem console.
- Acessos e contas podem ter validade; sessões podem expirar por tempo; códigos de acesso são de
  uso único. Senhas com argon2id, tokens de 256 bits.
- A senha do grupo viaja para o cliente de quem tem acesso ao address book (é assim que o cliente
  conecta sem pedir). Ao encerrar um terceiro, **rotacione a senha do grupo** (Grupos → rotacionar)
  e reaplique nas máquinas com o script — ou, melhor, ligue a autorização pelo hbbs abaixo.

## Autorização das conexões pelo hbbs

A senha da máquina é conferida pela própria máquina, mas **quem decide se a conexão acontece é o
hbbs**: sem punch hole nem relay não há sessão. Todo pedido de conexão leva ao hbbs o token de
login do usuário (por isso o cliente exige o `secure_tcp`), e o hbbs deste fork pode consultar esta
API antes de intermediar:

- sem token válido, só máquinas de grupos **sem** "exigir login";
- equipe e administradores logados: todas as máquinas;
- externos: só as máquinas dos grupos concedidos, com o acesso dentro da validade.

Resultado: uma senha copiada não serve sem sessão válida. Sessão vencida ou *Derrubar sessões* no
console = nenhuma conexão nova, na hora. As recusas ficam em **Auditoria → Recusadas**, com IP,
usuário e motivo; o cliente vê o motivo na tela.

Para ligar:

1. No hbbs (fork [iget-master/rustdesk-server](https://github.com/iget-master/rustdesk-server)),
   defina as variáveis mostradas em **Configurações → Integração com o hbbs** e reinicie-o:
   ```yaml
   environment:   # nos dois serviços, hbbs e hbbr
     - API_AUTH_URL=http://127.0.0.1:21114/api/internal/authorize
     - API_AUTH_SECRET=<segredo de Configurações>
   ```
2. Em cada grupo que deve ficar fechado, marque **Política de conexão → Exigir login para
   conectar**. Os demais grupos continuam como antes.

**Relay fechado**: o hbbs informa à API a sessão de cada relay que autorizou, e o hbbr
(configurado com as mesmas duas variáveis) consulta a API antes de parear duas conexões,
recusando sessões não anunciadas. Assim nem um cliente modificado com a chave do servidor
consegue usar o relay.

**Política global** (*Configurações → Integração com o hbbs*): "Bloquear conexões a máquinas
fora de grupo" faz o hbbs recusar qualquer destino que não esteja cadastrado em um grupo,
inclusive IDs desconhecidos. É o que fecha o servidor para quem só tem o endereço e a chave: dá
para registrar um ID no hbbs, mas nenhuma conexão é intermediada até um administrador colocar a
máquina num grupo.

Limites: a checagem é feita ao abrir a conexão (uma sessão já aberta não cai quando o token vence);
acesso por IP direto não passa pelo hbbs (`direct-server` vem desligado — dá para forçar `N` nas
opções do grupo); todo mundo que conecta nesses grupos precisa estar logado no cliente, inclusive
o celular. Se o hbbs não consegue falar com a API, ele recusa as conexões (`API_AUTH_FAIL_OPEN=Y`
inverte isso).

## Desenvolvimento

```bash
cargo build
RUSTDESK_API_DB_PATH=/tmp/dev.db cargo run -- user add admin --password admin --admin
RUSTDESK_API_DB_PATH=/tmp/dev.db cargo run -- serve --bind 127.0.0.1:21114
RD_PASS=admin ./scripts/smoke-test.sh      # contrato do cliente (curl)
RD_PASS=admin ./scripts/console-test.sh    # console ponta a ponta (curl + jq)
```

Backup: copie `rustdesk-api.db` com o serviço parado, ou `sqlite3 rustdesk-api.db ".backup b.db"`.
Testando o container dentro do WSL, use um volume nomeado em vez de `./data` em `/mnt/c`.

## Cliente personalizado (RustdeskOlirio)

O repositório [iget-master/rustdesk-olirio-client](https://github.com/iget-master/rustdesk-olirio-client)
gera um cliente Windows com nome próprio a partir da última release oficial do RustDesk, com
servidor, relay, API e chave fixos e **a senha permanente gerenciada por esta API**: o cliente
aplica a senha que a API devolver no heartbeat. **Toda máquina que está num grupo recebe a senha
do grupo** — basta atribuí-la a um grupo no console; não precisa de token nem de tocar na
máquina. O token de matrícula (`enroll_token`, gravado na instalação com `--option enroll-token`)
é opcional: serve para a máquina entrar no grupo sozinha e para o cliente informar a tag da senha
que aplicou (confirmação exata). Sem token, o servidor usa `devices.password_synced` para não
reenviar a cada heartbeat — zerado quando a máquina troca de grupo e quando a senha é rotacionada,
de modo que a senha nova sempre chega no próximo heartbeat. Rotacionar a senha no console atualiza
todas as máquinas do grupo em segundos.

O cliente personalizado também manda o `lan_ip` (o IPv4 da máquina na rede local) em cada
heartbeat, exibido na coluna **IP na LAN** e pesquisável na busca de dispositivos — útil para
achar a máquina dentro da rede do posto. O cliente comum não manda esse campo, e um heartbeat
sem ele preserva o último IP conhecido.

Para usar: em *Configurações*, envie o instalador gerado pelo build em **Instaladores no
servidor** (ou deixe o workflow enviar sozinho), clique em *usar no script* e informe o nome do
app em **Cliente personalizado**; os scripts de instalação passam a instalar esse cliente. Os
instaladores ficam em `<pasta do banco>/downloads` e são servidos em `/downloads/<nome>` só
para quem apresenta o token de matrícula de um grupo (`X-Enroll-Token`, que o script já
envia) ou uma sessão de administrador — o repositório do cliente é privado porque o instalador
carrega o endereço e a chave do seu servidor. A coluna
**Senha** em *Dispositivos* mostra `sincronizada`, `pendente` (ainda não confirmou a senha atual)
ou `manual` (RustDesk comum, senha só pelo script).

## Limitações conhecidas

- A senha permanente das máquinas não é empurrável pelo servidor (limite do cliente): entra via
  script de instalação ou `rustdesk --password`. Rotacionar no console atualiza o address book;
  as máquinas precisam do script de novo.
- Sem OIDC, e-mail ou TOTP de aplicativo (o segundo fator é o código emitido no console).
- Uma sessão remota já aberta não cai quando o token do usuário expira; o que expira é o acesso
  ao address book e novos logins.
- Um só inquilino: todos os administradores veem tudo.
