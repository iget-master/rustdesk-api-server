# RustDesk — endpoints HTTP que o cliente usa (referência para implementar um backend próprio)

Levantamento feito a partir do código-fonte do cliente em `rustdesk/` (commit `d453a19`, 2026-09-04),
cobrindo o núcleo Rust (`src/`), a UI Flutter (`flutter/lib/`) e a UI legada Sciter (`src/ui/*.tis`).
Toda referência de arquivo abaixo é relativa a `rustdesk/`.

> O cliente RustDesk fala com **dois** servidores distintos:
> 1. **hbbs/hbbr** (rendezvous + relay, portas 21116/21117, protocolo binário protobuf) — não é HTTP e não está coberto aqui.
> 2. **API server** (HTTP/JSON, porta padrão 21114) — é este que você quer reimplementar. É a parte que na versão paga chama-se *RustDesk Server Pro*; o `rustdesk-server` open-source **não implementa nenhum destes endpoints**, por isso o cliente trata a maioria dos erros como "opcional".

---

## 1. Como o cliente descobre o servidor de API

`src/common.rs:1104-1141` (`get_api_server`)

| Prioridade | Origem | Resultado |
|---|---|---|
| 1 | (Windows) licença embutida no nome do executável (`get_license_from_exe_name`) | campo `api` da licença |
| 2 | opção `api-server` (Configurações → Rede → *API Server*) | usada como está |
| 3 | opção `custom-rendezvous-server` (*ID Server*) | `http://<host>:21114` — se o ID server tiver porta explícita `P`, usa `http://<host>:(P-2)` |
| 4 | nada configurado | `https://admin.rustdesk.com` (público, e por isso a maior parte das chamadas é **desligada**) |

Regras adicionais:
- barra final é removida; `https://host:21114` vira `https://host` a menos que a opção builtin `allow-https-21114=Y` esteja definida;
- se a opção builtin `register-device=N` estiver ativa, `get_api_server()` devolve `""` e **nenhuma** chamada é feita;
- hosts `rustdesk.com` / `*.rustdesk.com` são considerados públicos (`is_public`): heartbeat, sysinfo, auditoria, switch-grant e upload de gravação **não** são enviados para eles.

Precisa aceitar **HTTP puro e HTTPS** (inclusive certificado auto-assinado — ver §6).

---

## 2. Convenções gerais

- **Autenticação de usuário**: `Authorization: Bearer <access_token>` (`flutter/lib/common.dart:2728`). O token vem de `/api/login` ou do fluxo OIDC e fica salvo localmente em `access_token`.
- **Autenticação de dispositivo** (chamadas feitas pelo serviço em background — heartbeat, sysinfo, auditoria do lado controlado, switch-grant): **sem header**. O dispositivo se identifica pelos campos `id` (ID RustDesk) e `uuid` (base64 do *machine uid*, `hbb_common::get_uuid()`), e o servidor confia neles porque o mesmo par `id`/`uuid`/`pk` foi registrado no hbbs (`RegisterPk`).
- **Erros**: um objeto JSON com chave `"error": "mensagem"` é tratado como falha **mesmo com HTTP 200**. A mensagem é exibida ao usuário (passa por `translate()`, então textos iguais aos do servidor oficial ganham tradução).
- **Sucesso em mutações**: HTTP 200 com corpo vazio (ou `null`).
- **Paginação** (listas): query `?current=<página começando em 1>&pageSize=100` → resposta `{"total": N, "data": [...]}`; o cliente repete enquanto `current*pageSize < total`.
- **HTTP 401** em qualquer chamada autenticada → o cliente descarta o token e volta ao estado "deslogado" (`/api/currentUser` também faz isso com 400).
- **HTTP 404** em `/api/ab/personal` → cliente entra em *modo legado* de address book; 404 em `/api/ab/settings` ou `/api/ab/shared/profiles` → "servidor sem address book compartilhado".
- `Content-Type: application/json` em tudo; POSTs sem corpo levam `Content-Length: 0`.
- Timeouts: 12 s por tentativa no caminho Rust; 30 s no caminho Dart; 2 s no `/api/logout`.

---

## 3. Tabela-resumo

| # | Método | Caminho | Auth | Quem chama | Finalidade |
|---|---|---|---|---|---|
| 1 | GET | `/api/login-options` | — | UI (login) / Rust (sonda TLS) | Lista provedores OIDC disponíveis |
| 2 | POST | `/api/login` | — | UI | Login com usuário/senha; 2ª etapa e-mail/2FA |
| 3 | POST | `/api/logout` | Bearer | UI | Invalida token |
| 4 | POST | `/api/currentUser` | Bearer | UI (ao abrir) | Valida token e devolve dados do usuário |
| 5 | POST | `/api/oidc/auth` | — | Rust (`account.rs`) | Inicia login OIDC, devolve URL do provedor |
| 6 | GET | `/api/oidc/auth-query` | — | Rust (polling 1 s) | Verifica se o OIDC concluiu; devolve token |
| 7 | POST | `/api/ab/personal` | Bearer | UI | GUID do address book pessoal (detecta modo novo/legado) |
| 8 | POST | `/api/ab/settings` | Bearer | UI | Limites (`max_peer_one_ab`) |
| 9 | POST | `/api/ab/shared/profiles` | Bearer | UI | Lista de address books compartilhados |
| 10 | POST | `/api/ab/peers?ab=<guid>` | Bearer | UI | Peers de um address book |
| 11 | POST | `/api/ab/tags/{guid}` | Bearer | UI | Tags (nome + cor) de um address book |
| 12 | POST | `/api/ab/peer/add/{guid}` | Bearer | UI | Adiciona peer |
| 13 | PUT | `/api/ab/peer/update/{guid}` | Bearer | UI | Atualiza campos de um peer |
| 14 | DELETE | `/api/ab/peer/{guid}` | Bearer | UI | Remove peers |
| 15 | POST | `/api/ab/tag/add/{guid}` | Bearer | UI | Cria tag |
| 16 | PUT | `/api/ab/tag/rename/{guid}` | Bearer | UI | Renomeia tag |
| 17 | PUT | `/api/ab/tag/update/{guid}` | Bearer | UI | Muda cor da tag |
| 18 | DELETE | `/api/ab/tag/{guid}` | Bearer | UI | Remove tags |
| 19 | GET | `/api/ab` | Bearer | UI (modo legado) | Baixa address book inteiro (blob JSON) |
| 20 | POST | `/api/ab` | Bearer | UI (modo legado) | Sobe address book inteiro |
| 21 | POST | `/api/ab/get` | Bearer | UI Sciter (obsoleta) | Versão antiga do #19 |
| 22 | GET | `/api/device-group/accessible` | Bearer | UI (aba Grupo) | Grupos de dispositivos visíveis |
| 23 | GET | `/api/users` | Bearer | UI (aba Grupo) | Usuários visíveis |
| 24 | GET | `/api/peers` | Bearer | UI (aba Grupo) | Dispositivos visíveis |
| 25 | POST | `/api/heartbeat` | — (id/uuid) | Serviço, 15 s / 3 s | Presença, conexões ativas, recebe estratégia/desconexões |
| 26 | POST | `/api/sysinfo` | — (id/uuid) | Serviço | Inventário de hardware/SO + campos de provisionamento |
| 27 | POST | `/api/sysinfo_ver` | — | Serviço | (código morto — nunca chega a ser chamado) |
| 28 | POST | `/api/audit/conn` | — (id/uuid) | Serviço (lado controlado) / UI (nota) | Log de conexões |
| 29 | POST | `/api/audit/file` | — (id/uuid) | Serviço | Log de transferência de arquivos |
| 30 | POST | `/api/audit/alarm` | — (id/uuid) | Serviço | Alarmes de segurança |
| 31 | GET | `/api/audit/conn/active` | Bearer | UI (lado controlador) | GUID do registro de auditoria da sessão atual |
| 32 | PUT | `/api/audit` | Bearer | UI | Anexa nota a um registro de auditoria |
| 33 | POST | `/api/devices/deploy` | Bearer (token de admin) | CLI/UI | Registra dispositivo quando hbbs responde `NOT_DEPLOYED` |
| 34 | POST | `/api/devices/cli` | Bearer (token de admin) | CLI `--assign` | Atribui dispositivo a usuário/estratégia/grupo/AB |
| 35 | POST | `/api/switch-grant` | — (assinatura ed25519) | Rust | Autoriza "trocar lados" (switch sides) |
| 36 | POST | `/api/record?type=...` | — | Serviço | Upload incremental de gravação (dormente no client OSS) |

Fora do seu backend (chamadas a terceiros): `POST https://api.rustdesk.com/version/latest` (checagem de atualização) e `https://api.telegram.org/bot<token>/{sendMessage,getUpdates}` (envio do código 2FA por Telegram).

---

## 4. Detalhamento por grupo

### 4.1 Conta e autenticação

#### `GET /api/login-options`
`flutter/lib/models/user_model.dart:240-264`, `src/hbbs_http/account.rs:155`, `src/hbbs_http/record_upload.rs:34`

- Sem autenticação. Também é usado pelo Rust apenas como **sonda TLS** (`HEAD`) para descobrir qual implementação TLS funciona com o servidor — responda a `HEAD` sem erro.
- Resposta: **array JSON de strings**. Dois formatos aceitos:
  - antigo: `["oidc/github", "oidc/google", ...]` → nome do provedor após `oidc/`;
  - novo: um item `"common-oidc/<json>"`, onde `<json>` é um array `[{"name": "github", "icon": "<url ou data-uri>"}, ...]`. Se existir, tem precedência.
- Lista vazia `[]` = só login com senha.

#### `POST /api/login`
`flutter/lib/models/user_model.dart:193-235`, `flutter/lib/common/hbbs/hbbs.dart:133-197`, `flutter/lib/common/widgets/login.dart:842-848, 1016-1024`

Corpo (etapa 1 — usuário e senha):
```json
{
  "username": "alice",
  "password": "segredo",
  "id": "123456789",
  "uuid": "<base64 machine-uid>",
  "autoLogin": true,
  "type": "account",
  "deviceInfo": { "os": "windows", "type": "client", "name": "HOSTNAME" }
}
```
Respostas possíveis (HTTP 200):
```json
// login concluído
{ "access_token": "…", "type": "access_token", "user": { …UserPayload… } }

// precisa de verificação por e-mail ou 2FA (TOTP) — etapa 2
{ "type": "email_check", "tfa_type": "email_check" | "tfa_check", "secret": "<opaco>", "user": { "name": "alice" } }

// erro
{ "error": "Wrong password" }
```
Corpo (etapa 2 — código):
```json
{
  "verificationCode": "123456",
  "tfaCode": "123456",            // só quando tfa_type == "tfa_check"
  "secret": "<o mesmo secret recebido>",
  "username": "alice",
  "id": "…", "uuid": "…",
  "autoLogin": true,
  "type": "email_code",
  "deviceInfo": { … }
}
```
Constantes de `type` conhecidas pelo cliente: requisição `account`, `mobile`, `sms_code`, `email_code`, `tfa_code`; resposta `access_token`, `email_check`, `tfa_check`.

Status HTTP ≠ 200 com `{"error": …}` também é tratado (mostra `HTTP <código>` se o corpo não for JSON).

**`UserPayload`** (campos lidos pelo cliente, `hbbs.dart:26-48` e `account.rs:79-97`):
```json
{
  "name": "alice",              // obrigatório — usado como chave de identidade
  "display_name": "Alice",
  "avatar": "/avatar/xxx.png",  // caminho relativo é resolvido contra o api-server (ui_interface.rs:253)
  "email": "", "note": "",
  "status": 1,                  // 1 normal, 0 desabilitado, -1 não verificado
  "is_admin": false,
  "verifier": "…",              // só web
  "info": { "email_verification": false, "email_alarm_notification": false, "login_device_whitelist": [], "other": {} },
  "third_auth_type": null
}
```

#### `POST /api/logout`
`user_model.dart:170-190` — Bearer; corpo `{"id","uuid"}`; timeout de 2 s; **resposta ignorada** (o cliente apaga o token localmente de qualquer forma). Chamado também quando o usuário troca o servidor de API estando logado (`common.dart:3636`).

#### `POST /api/currentUser`
`user_model.dart:53-114` — Bearer; corpo `{"id","uuid"}`. Chamado ao iniciar o app se houver token salvo. Resposta: `UserPayload` ou `{"error": …}`. HTTP **401** → apaga token, address book e grupo; **400** → apaga só o token.

#### `POST /api/oidc/auth` e `GET /api/oidc/auth-query`
`src/hbbs_http/account.rs:160-199, 249-348`

1. `POST /api/oidc/auth` (sem auth):
   ```json
   { "op": "github", "id": "…", "uuid": "…", "deviceInfo": {…}, "apiDomain": "https://seu-api" }
   ```
   Resposta: `{ "code": "<id da tentativa>", "url": "https://provedor/authorize?…" }`. O cliente abre `url` no navegador.
2. `GET /api/oidc/auth-query?code=<code>&id=<id>&uuid=<uuid>` a cada **1 s por até 3 min**.
   - Enquanto pendente: `{"error": "No authed oidc is found"}` (**exatamente este texto** — qualquer outro `error` aborta o fluxo).
   - Concluído: mesmo `AuthBody` do login: `{ "access_token", "type": "access_token", "tfa_type", "secret", "user": {…} }`.

---

### 4.2 Address book (formato atual — múltiplos address books)

Fluxo de carga (`flutter/lib/models/ab_model.dart:142-218`): `ab/personal` → (se novo) `ab/settings` → `ab/shared/profiles` → para o AB selecionado `ab/peers` + `ab/tags/{guid}`. Todos com Bearer.

| Endpoint | Corpo | Resposta |
|---|---|---|
| `POST /api/ab/personal` | vazio | `{"guid": "<guid do AB pessoal>"}` — **404 = modo legado** |
| `POST /api/ab/settings` | vazio | `{"max_peer_one_ab": 0}` (0 = ilimitado) |
| `POST /api/ab/shared/profiles?current&pageSize` | vazio | `{"total": N, "data": [AbProfile]}` |
| `POST /api/ab/peers?current&pageSize&ab=<guid>` | vazio | `{"total": N, "data": [Peer]}` |
| `POST /api/ab/tags/{guid}` | vazio | `[ {"name": "prod", "color": 4283215696}, … ]` (color = int ARGB) |
| `POST /api/ab/peer/add/{guid}` | um `Peer` por chamada | 200 vazio ou `{"error"}` |
| `PUT /api/ab/peer/update/{guid}` | `{"id": "…", <campos alterados>}` | 200 vazio ou `{"error"}` |
| `DELETE /api/ab/peer/{guid}` | `["id1","id2"]` | 200 vazio ou `{"error"}` |
| `POST /api/ab/tag/add/{guid}` | `{"name","color"}` (uma por chamada) | 200 vazio ou `{"error"}` |
| `PUT /api/ab/tag/rename/{guid}` | `{"old","new"}` | idem |
| `PUT /api/ab/tag/update/{guid}` | `{"name","color"}` | idem |
| `DELETE /api/ab/tag/{guid}` | `["tag"]` | idem |

**`AbProfile`** (`hbbs.dart:258-275`): `{"guid","name","owner","note","info","rule"}` — `rule`: 1 = leitura, 2 = leitura/escrita, 3 = controle total (`ShareRule`). O AB pessoal é inserido pelo próprio cliente com o `guid` de `/api/ab/personal`; não precisa vir em `shared/profiles`.

**`Peer`** (`flutter/lib/models/peer_model.dart:33-68`) — como aparece em `data` de `ab/peers`:
```json
{
  "id": "123456789",
  "hash": "",             // senha em hash — só AB pessoal
  "password": "",         // senha em claro — só AB compartilhado
  "username": "alice", "hostname": "PC-01", "platform": "Windows",
  "alias": "Servidor",
  "tags": ["prod"],
  "forceAlwaysRelay": "false",   // string, não bool
  "rdpPort": "", "rdpUsername": "",
  "loginName": "",
  "device_group_name": "",
  "note": "",
  "same_server": true      // opcional; se true o cliente não sobrescreve username/hostname/platform
}
```
Campos enviados em `peer/update` (`ab_model.dart:1581-1749`): `tags` (array), `alias`, `note`, `hash` (pessoal) ou `password` (compartilhado), e na sincronização automática com sessões recentes `username`/`hostname`/`platform`/`hash`. Em `peer/add` o cliente remove `password` no AB pessoal e `hash` no compartilhado antes de enviar.

Permissões: o cliente respeita `rule` localmente (esconde botões), mas o servidor deve validar.

### 4.3 Address book legado (um único AB por usuário)

Ativado quando `/api/ab/personal` responde **404**. `ab_model.dart:1008-1096`.

- `GET /api/ab` (Bearer, `Accept-Encoding: gzip`) → `{"data": "<string JSON>", "licensed_devices": 0}`; corpo literal `null` = AB vazio. O conteúdo de `data` (string, não objeto!) é:
  ```json
  {"tags": ["prod"], "peers": [{"id","username","hostname","platform","alias","tags","hash"}], "tag_colors": "{\"prod\": 4283215696}"}
  ```
- `POST /api/ab` (Bearer) corpo `{"data": "<string JSON acima>"}` → 200 vazio/`null`.
- UI Sciter antiga (`src/ui/ab.tis:650`): `POST /api/ab/get` corpo `{}` → `{"updated_at": …, "data": "<string JSON>"}`.

Se você implementar só o formato novo, responda 404 em `/api/ab/get` e não precisa de `/api/ab`. Se implementar só o legado, responda 404 em `/api/ab/personal`.

### 4.4 Aba "Grupo" (dispositivos e usuários acessíveis)

`flutter/lib/models/group_model.dart:103-282`. Todos GET, Bearer, paginados com `current`/`pageSize`.

| Endpoint | Query extra | Item de `data` |
|---|---|---|
| `/api/device-group/accessible` | — | `{"name": "TI"}` (falha é silenciosa — servidores antigos não têm) |
| `/api/users` | `accessible=&status=1` | `UserPayload` (usa `name`, `display_name`) |
| `/api/peers` | `accessible=&status=1` | `{"id","info":{"username","os":"Windows / 10","device_name"},"status","user","user_name","device_group_name","note"}` |

Se `error` contiver `"disabled"` (ex.: `Retrieving accessible devices is disabled.`) o cliente limpa a aba sem mostrar erro; `"Admin required!"` gera dica de upgrade. Primeiro campo de `info.os` (antes de ` / `) é mapeado para plataforma: `windows|linux|macos|android`.

---

### 4.5 Telemetria do dispositivo (serviço em background)

`src/hbbs_http/sync.rs:86-285`. Roda no serviço (`--server`), **não** em clientes *outgoing-only*, nem quando `stop-service`, nem para servidores públicos.

#### `POST /api/heartbeat`
Cadência: timer de 3 s; envia a cada **15 s** sem conexões ativas e a cada **3 s** quando há conexões.
```json
{ "id": "123456789", "uuid": "<b64>", "ver": 1004020, "conns": [1, 2], "modified_at": 1710000000 }
```
- `ver` = número derivado da versão (`get_version_number`: `1.4.2` → `1004020`; `1.1.10` → `1001100`).
- `conns` só aparece se houver conexões; são os `conn_id` das sessões recebidas.
- `modified_at` = timestamp da última **estratégia** aplicada (opção local `strategy_timestamp`, 0 se nenhuma).

Resposta (todas as chaves opcionais; `{}` é válido):
```json
{
  "sysinfo": true,                 // qualquer valor → força reenvio de /api/sysinfo
  "disconnect": [1],               // conn_ids que o servidor manda derrubar
  "modified_at": 1710000500,       // se ≠ do enviado, cliente grava o novo valor
  "strategy": {                    // aplica opções remotamente (Config::set_options)
    "config_options": { "enable-file-transfer": "N", "direct-server": "" },
    "extra": {}
  }
}
```
`config_options` aceita qualquer chave de `libs/hbb_common/src/config.rs` (módulo `keys`); valor vazio remove a opção do usuário (volta ao padrão builtin).

#### `POST /api/sysinfo`
Enviado no primeiro tick após iniciar, quando o usuário logado no SO muda, quando servidor/ID mudam, ou quando o heartbeat responde com `sysinfo`. Corpo (`src/common.rs:914-958` + `sync.rs:131-179`):
```json
{
  "cpu": "Intel Core i7, 3.2GHz, 8/4 cores",
  "memory": "16GB",
  "os": "windows / Windows 11 Pro - 10.0.26200",
  "hostname": "PC-01",
  "username": "alice",             // usuário ativo do SO (omitido se vazio/SYSTEM)
  "version": "1.4.2",
  "id": "123456789",
  "uuid": "<b64>",
  "preset-address-book-name": "…", "preset-address-book-tag": "…",   // opcionais, só se
  "preset-address-book-alias": "…", "preset-address-book-password": "…", // configurados
  "preset-address-book-note": "…",
  "preset-user-name": "…", "preset-strategy-name": "…", "preset-device-group-name": "…",
  "preset-note": "…"
}
```
(`preset-device-username` / `preset-device-name`, se definidos, **substituem** `username` / `hostname`.)
Resposta em **texto puro**: `SYSINFO_UPDATED` (sucesso — o cliente não reenvia até algo mudar), `ID_NOT_FOUND` (reenvia no próximo heartbeat), qualquer outra coisa (reenvia após 120 s).

Os campos `preset-*` são a forma de **auto-provisionamento**: um instalador/configuração pré-definida diz ao servidor a qual usuário/grupo/AB/estratégia o dispositivo pertence.

#### `POST /api/sysinfo_ver`
Só seria chamado quando `is_public(url)` é verdadeiro, mas `heartbeat_url()` devolve vazio nesse caso (`sync.rs:181-209, 276-285`). **Inalcançável** — ignore.

---

### 4.6 Auditoria

URL base: `get_audit_server()` = `<api>/api/audit/<tipo>` (`src/common.rs:1182`). Postagens do serviço não levam token; usam `id`/`uuid`. Todas incluem `nonce` (UUID v4) — o servidor deve **deduplicar por nonce** (guarde ~5 min): o cliente reenvia em erro de transporte, 5xx, 408/429 ou corpo `{"error"}`, com backoff 10 s/30 s dentro de 120 s (`src/server/connection.rs:1532-1629`). Sucesso = 2xx com corpo **vazio**.

#### `POST /api/audit/conn` — lado controlado (`connection.rs:1385-1434, 1777-1784, 1098`)
Três eventos por sessão, sempre com `id`, `uuid`, `conn_id`, `session_id`, `nonce`:
```json
{ "action": "new", "ip": "203.0.113.5", "conn_audit_ref": "…", "id": "…", "uuid": "…", "conn_id": 3, "session_id": 1234567890, "nonce": "…" }
{ "peer": ["987654321", "Nome do controlador"], "type": 0, "primary_auth": 3, "two_factor": 1, … }   // após autenticar
{ "action": "close", … }
```
- `type`: 0 remoto, 1 transferência de arquivo, 2 port-forward/RDP, 3 câmera, 4 terminal.
- `primary_auth`: 1 clique (aceite manual), 2 senha temporária, 3 senha permanente, 4 switch sides. `two_factor`: 1 TOTP, 2 dispositivo confiável.
- `conn_audit_ref` vem do hbbs (`ControlledContext.conn_audit_ref` no protobuf) — só existe se o seu hbbs o preencher; pode ignorar.

Também no mesmo caminho, mas vindo do **lado controlador** (`src/ui_session_interface.rs:583-590, 2065-2069`): `{"id": "<peer controlado>", "session_id": 1234, "note": "texto"}` — nota escrita durante a sessão. Só é enviado se houver `access_token` salvo, mas o header **não** é incluído.

#### `POST /api/audit/file` (`connection.rs:1452-1487`)
```json
{
  "id": "…", "uuid": "…", "peer_id": "987654321", "conn_id": 3,
  "type": 0,                      // 0 = RemoteSend (arquivo saiu daqui), 1 = RemoteReceive
  "path": "C:\\Users\\alice\\Docs",
  "is_file": false,
  "info": "{\"ip\":\"…\",\"name\":\"controlador\",\"num\":12,\"files\":[[\"a.zip\",1048576],…]}",  // string JSON, 10 maiores arquivos
  "nonce": "…"
}
```

#### `POST /api/audit/alarm` (`connection.rs:1489-1513, 6239-6251`)
```json
{ "id": "…", "uuid": "…", "typ": 0, "info": "{\"ip\":\"…\"}", "conn_id": 3, "nonce": "…", "conn_audit_ref": "…" }
```
`typ`: 0 IP fora da whitelist, 1 >30 tentativas, 2 6 tentativas em 1 min, 6 excesso de tentativas por prefixo IPv6, 7 backoff de login no terminal, 8 concorrência de login no terminal, 9 violação de escopo de sessão, 10 ID fora da whitelist. `info` é string JSON com `ip`, `id`, `name`, etc.

#### `GET /api/audit/conn/active?id=<peer>&session_id=<n>&conn_type=<0-4>` (`flutter/lib/models/model.dart:1252-1337`)
Bearer. Chamado pelo controlador ao conectar (até 6 tentativas) quando a opção *pedir nota ao fim da conexão* está ativa. Resposta: **string JSON** com o GUID do registro (`"a1b2…"`).

#### `PUT /api/audit` (`flutter/lib/common/widgets/dialog.dart:1650-1681`)
Bearer; corpo `{"guid": "<do endpoint acima>", "note": "…"}` → 200.

---

### 4.7 Provisionamento de dispositivos

#### `POST /api/devices/deploy` (`src/ui_interface.rs:1081-1150`)
Disparado por `rustdesk --deploy --token <token> [--id <novo id>]` ou pela UI Android quando o hbbs responde `RegisterPkResponse::NOT_DEPLOYED` (`src/rendezvous_mediator.rs:359-371`). Header `Authorization: Bearer <token de API/admin>`.
```json
{ "id": "123456789", "uuid": "<b64>", "pk": "<b64 chave pública ed25519 do dispositivo>" }
```
Resposta: `{"result": "OK" | "NOT_ENABLED" | "INVALID_INPUT" | "ID_TAKEN"}`. Com `OK` e `--id`, o cliente troca o próprio ID localmente. Só faz sentido se o **seu hbbs** também implementar a política "dispositivo precisa estar deployado"; caso contrário responda `NOT_ENABLED`.

#### `POST /api/devices/cli` (`src/core_main.rs:541-645`)
`rustdesk --assign --token <token> [--user_name U] [--strategy_name S] [--address_book_name AB --address_book_tag T --address_book_alias A --address_book_password P --address_book_note N] [--device_group_name G] [--note N] [--device_username U] [--device_name N]`
```json
{ "id": "…", "uuid": "…", "user_name": "alice", "address_book_name": "…", "device_group_name": "…", … }
```
Resposta: corpo vazio = sucesso (imprime `Done!`); qualquer texto é impresso como está.

---

### 4.8 Switch sides — `POST /api/switch-grant` (`src/hbbs_http/sync.rs:312-407`)
Fire-and-forget quando o usuário controlador clica em "trocar lados". Sem token; autenticado por **assinatura ed25519** com a chave privada do dispositivo (a pública é a mesma registrada no hbbs via `RegisterPk`).
```json
{ "id": "123456789", "switch_code_verifier": "<b64>", "timestamp": "1710000000", "signature": "<b64>" }
```
- `switch_code = b64(sha256(switch_uuid))`; `switch_code_verifier = b64(sha256("switch-grant-verifier\0" + switch_code))`;
- mensagem assinada: `"switch-grant\0" + id + "\0" + switch_code_verifier + "\0" + timestamp` (segundos Unix).
- Resposta: `{"accepted": true}`; se o relógio estiver fora da janela, `{"accepted": false, "server_time": 1710000123}` → cliente reassina com `server_time` e tenta **uma** vez. O `switch_code` bruto chega ao hbbs no `PunchHoleRequest.switch_code`; o servidor de API e o hbbs precisam compartilhar estado para validar. Se não usar, responda `{"accepted": true}`.

### 4.9 Upload de gravação — `POST /api/record` (`src/hbbs_http/record_upload.rs`)
Query `type=new|part|tail|remove&file=<nome>[&offset=&length=]`, corpo = bytes brutos do vídeo. A flag `ENABLE` nunca é ligada no cliente open-source (`record_upload.rs:20-25`), então **não é chamado** — documentado apenas por completude.

---

## 5. Chamadas a terceiros (não implementar)

- `POST https://api.rustdesk.com/version/latest` — `{"os","os_version","arch","device_id","typ":"rustdesk-client"}` → `{"url": "https://github.com/rustdesk/rustdesk/releases/tag/1.4.2"}` (`src/common.rs:998-1057`, `libs/hbb_common/src/lib.rs:473-515`). Desligado em clientes custom ou com `enable-check-update` off.
- Telegram Bot API — código 2FA de conexão via bot (`src/auth_2fa.rs:158-204`).

---

## 6. Transporte: detalhes que afetam o backend

- **Dois clientes HTTP** (`flutter/lib/utils/http_service.dart:12-45`): por padrão a UI Flutter usa o `http` do Dart (timeout 30 s); com proxy configurado ou opção `enable-flutter-http-on-rust=Y` as chamadas passam pelo Rust (`http_request_sync`, `src/common.rs:1764`). Heartbeat/sysinfo/auditoria/OIDC/deploy sempre usam o Rust (`post_request`, `common.rs:1462`).
- **TLS com fallback** (`src/hbbs_http/http_client.rs`, `common.rs:1525-1607`): tenta rustls → rustls aceitando certificado inválido → native-tls; o resultado fica em cache por host. Na prática **certificado auto-assinado funciona** para os endpoints Rust; para o caminho Dart (UI) o certificado precisa ser válido, então em produção use HTTPS válido ou HTTP puro atrás de rede confiável.
- **Proxy TCP bruto via hbbs** (`common.rs:1190-1312`, `libs/hbb_common/protos/rendezvous.proto:224-241`): se a opção builtin `use-raw-tcp-for-api=Y` estiver ativa, ou como fallback após falha de conexão/5xx, o cliente encapsula a requisição em `HttpProxyRequest{method,path,headers,body}` e a envia ao **hbbs** (porta 21116, canal cifrado com a chave do servidor), esperando `HttpProxyResponse{status,headers,body,error}`. Só importa se você também implementar o hbbs; um `rustdesk-server` OSS não responde a isso e o cliente simplesmente registra o erro.
- `reqwest` sem proxy de sistema (`no_proxy()`), respeita apenas o proxy SOCKS5/HTTP configurado no próprio RustDesk.

---

## 7. Roteiro sugerido para um backend mínimo

1. **Servir 404 rápido** para tudo que não implementar — o cliente foi escrito para conviver com servidores parciais.
2. **Login básico**: `GET /api/login-options` → `[]`; `POST /api/login` → `{access_token, type:"access_token", user}`; `POST /api/currentUser`; `POST /api/logout`.
3. **Address book novo**: `ab/personal` (gera um GUID por usuário), `ab/settings`, `ab/shared/profiles` (pode devolver `{"total":0,"data":[]}`), `ab/peers`, `ab/tags/{guid}` e as mutações de peer/tag. Responda 404 em `/api/ab/get` para afastar a UI Sciter.
4. **Aba Grupo**: `/api/users`, `/api/peers`, `/api/device-group/accessible` — dá o "painel de dispositivos online" quando combinado com o heartbeat.
5. **Heartbeat + sysinfo**: é o que preenche o inventário e permite `disconnect`/`strategy`. Lembre-se: só chega de servidores não-públicos e o dispositivo se identifica por `id`+`uuid`.
6. **Auditoria**: `audit/conn`, `audit/file`, `audit/alarm` com dedup por `nonce`; depois `audit/conn/active` + `PUT /api/audit` para notas.
7. Opcional: OIDC (`oidc/auth`, `oidc/auth-query`), `devices/deploy` + `devices/cli` (requer cooperação do hbbs), `switch-grant`.

Para inspiração de implementações abertas compatíveis, procure por "rustdesk-api" no GitHub (há projetos em Go e Node que reimplementam este mesmo contrato); este documento reflete o que o cliente **atual** envia e espera, que é a fonte de verdade.
