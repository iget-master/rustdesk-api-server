#!/usr/bin/env bash
# Ponta a ponta do console: grupo -> matrícula -> strategy no heartbeat -> usuário externo com
# código de acesso -> address book escopado -> rotação de senha -> derrubar sessão. Requer jq.
#   API=http://127.0.0.1:21114 RD_USER=admin RD_PASS=senha ./scripts/console-test.sh
set -euo pipefail
API=${API:-http://127.0.0.1:21114}
RD_USER=${RD_USER:-admin}
RD_PASS=${RD_PASS:?defina RD_PASS}
DEV=${DEV:-555000111}
GROUP="Grupo Teste $RANDOM"
EXT="suporte-$RANDOM"

j() { curl -sS -H 'Content-Type: application/json' "$@"; }
code() { curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' "$@"; }
die() { echo "FALHOU: $1"; exit 1; }
# must "descrição" <json> <filtro jq>  — aborta se o filtro não for verdadeiro
must() { if jq -e "$3" >/dev/null 2>&1 <<< "$2"; then echo "ok  $1"; else echo "FALHOU: $1"; echo "  resposta: $2"; exit 1; fi; }
must_code() { [ "$2" = "$3" ] && echo "ok  $1 -> $2" || die "$1 -> HTTP $2 (esperado $3)"; }

echo "== login admin"
TOKEN=$(j -X POST "$API/api/login" -d "{\"username\":\"$RD_USER\",\"password\":\"$RD_PASS\",\"type\":\"account\",\"id\":\"t\",\"uuid\":\"t\"}" | jq -r .access_token)
[ "$TOKEN" != null ] && [ -n "$TOKEN" ] || die "login admin"
A="Authorization: Bearer $TOKEN"

echo "== configurações"
must "settings" "$(j -X PUT "$API/admin/api/settings" -H "$A" -d '{"server_host":"rd.example.com","server_key":"KEY123=","api_url":"http://api.example.com:21114","download_url":"https://example.com/rustdesk.exe"}')" '.server_host=="rd.example.com"'

echo "== grupo"
ST=$(j -X POST "$API/admin/api/groups" -H "$A" -d "{\"name\":\"$GROUP\",\"note\":\"teste\"}")
SID=$(echo "$ST" | jq -r .id); PASS=$(echo "$ST" | jq -r .password); ENROLL=$(echo "$ST" | jq -r .enroll_token); GUID=$(echo "$ST" | jq -r .ab_guid)
must "grupo criado com address book" "$ST" '.ab_guid != null and (.password|length) >= 8 and (.enroll_token|length) > 20'
must "opções padrão" "$ST" '.options["approve-mode"]=="password"'

echo "== matrícula via /api/enroll"
must_code "token inválido" "$(code -X POST "$API/api/enroll" -d "{\"token\":\"nope\",\"id\":\"$DEV\"}")" 403
must "enroll" "$(j -X POST "$API/api/enroll" -d "{\"token\":\"$ENROLL\",\"id\":\"$DEV\",\"hostname\":\"PDV-01\"}")" '.result=="OK"'
j -X POST "$API/api/sysinfo" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"hostname\":\"PDV-01\",\"username\":\"caixa\",\"os\":\"windows / Windows 10 Pro\",\"version\":\"1.4.2\",\"cpu\":\"i3\",\"memory\":\"8GB\"}" >/dev/null
must "dispositivo no grupo" "$(j "$API/admin/api/devices?group=$SID" -H "$A")" "map(select(.id==\"$DEV\" and .hostname==\"PDV-01\")) | length == 1"

echo "== strategy no heartbeat"
HB=$(j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":0}")
must "heartbeat entrega strategy" "$HB" '.strategy.config_options["approve-mode"]=="password" and .modified_at>0'
TS=$(echo "$HB" | jq -r .modified_at)
must "heartbeat sem strategy quando já aplicado" "$(j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":$TS}")" 'has("strategy")|not'
j -X PUT "$API/admin/api/groups/$SID" -H "$A" -d '{"options":{"approve-mode":"password","verification-method":"use-permanent-password","enable-file-transfer":"N"}}' >/dev/null
HB2=$(j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":$TS}")
must "opções alteradas chegam no próximo heartbeat" "$HB2" ".strategy.config_options[\"enable-file-transfer\"]==\"N\" and .modified_at > $TS"

echo "== usuário externo com código de acesso"
U=$(j -X POST "$API/admin/api/users" -H "$A" -d "{\"name\":\"$EXT\",\"password\":\"ext123\",\"kind\":\"external\",\"tfa\":\"console\",\"session_hours\":4}")
must "usuário externo criado" "$U" '.user.kind=="external" and .user.tfa=="console" and .user.session_hours==4'
UID_=$(echo "$U" | jq -r .user.id)
must "acesso somente leitura concedido" "$(j -X POST "$API/admin/api/grants" -H "$A" -d "{\"user_id\":$UID_,\"group_id\":$SID,\"rule\":1}")" '.rule==1'

STEP1=$(j -X POST "$API/api/login" -d "{\"username\":\"$EXT\",\"password\":\"ext123\",\"type\":\"account\",\"id\":\"e\",\"uuid\":\"e\"}")
must "login etapa 1 pede código" "$STEP1" '.type=="email_check" and .tfa_type=="tfa_check" and .user.name!=null'
SECRET=$(echo "$STEP1" | jq -r .secret)
must_code "código errado" "$(code -X POST "$API/api/login" -d "{\"type\":\"email_code\",\"secret\":\"$SECRET\",\"tfaCode\":\"000000\",\"verificationCode\":\"000000\",\"username\":\"$EXT\"}")" 401
CODE=$(j -X POST "$API/admin/api/users/$UID_/access-code" -H "$A" -d '{"ttl_minutes":5}' | jq -r .code)
[ ${#CODE} = 6 ] || die "código de acesso: $CODE"
STEP2=$(j -X POST "$API/api/login" -d "{\"type\":\"email_code\",\"secret\":\"$SECRET\",\"tfaCode\":\"$CODE\",\"verificationCode\":\"$CODE\",\"username\":\"$EXT\",\"id\":\"e\",\"uuid\":\"e\"}")
must "login etapa 2 com o código" "$STEP2" '.type=="access_token" and .access_token!=null'
EXT_TOKEN=$(echo "$STEP2" | jq -r .access_token)
E="Authorization: Bearer $EXT_TOKEN"
must_code "código é de uso único" "$(code -X POST "$API/api/login" -d "{\"type\":\"email_code\",\"secret\":\"$SECRET\",\"tfaCode\":\"$CODE\",\"verificationCode\":\"$CODE\"}")" 401

echo "== escopo do externo"
must "vê o AB do grupo (leitura)" "$(j -X POST "$API/api/ab/shared/profiles?current=1&pageSize=100" -H "$E" -H 'Content-Length: 0')" ".data | map(select(.guid==\"$GUID\" and .rule==1)) | length == 1"
must "AB traz a máquina com a senha do grupo" "$(j -X POST "$API/api/ab/peers?current=1&pageSize=100&ab=$GUID" -H "$E" -H 'Content-Length: 0')" ".data | map(select(.id==\"$DEV\" and .password==\"$PASS\" and .hostname==\"PDV-01\" and .platform==\"Windows\")) | length == 1"
must "aba Grupo só mostra o grupo" "$(j "$API/api/peers?current=1&pageSize=100" -H "$E")" ".total >= 1 and (.data | all(.device_group_name==\"$GROUP\"))"
must "não vê usuários" "$(j "$API/api/users?current=1&pageSize=100" -H "$E")" '.total==0'
must_code "somente leitura bloqueia edição" "$(code -X PUT "$API/api/ab/peer/update/$GUID" -H "$E" -d "{\"id\":\"$DEV\",\"alias\":\"x\"}")" 403
must_code "externo não acessa o console" "$(code "$API/admin/api/overview" -H "$E")" 403

echo "== rotação de senha"
NEW=$(j -X POST "$API/admin/api/groups/$SID/rotate-password" -H "$A" | jq -r .password)
[ "$NEW" != "$PASS" ] && [ ${#NEW} -ge 8 ] || die "rotação de senha"
must "AB atualizado com a nova senha" "$(j -X POST "$API/api/ab/peers?current=1&pageSize=100&ab=$GUID" -H "$E" -H 'Content-Length: 0')" ".data[0].password==\"$NEW\""
j "$API/admin/api/groups/$SID/install-script?os=windows" -H "$A" | grep -q -- "--password '$NEW'" && echo "ok  script Windows traz a senha nova" || die "script Windows"
j "$API/admin/api/groups/$SID/install-script?os=linux" -H "$A" | grep -q "$ENROLL" && echo "ok  script Linux traz o token de matrícula" || die "script Linux"

echo "== derrubar sessão"
j -X POST "$API/admin/api/users/$UID_/logout" -H "$A" >/dev/null
must_code "sessão do externo encerrada" "$(code -X POST "$API/api/currentUser" -H "$E" -d '{}')" 401

echo "== limpeza"
j -X DELETE "$API/admin/api/grants" -H "$A" -d "{\"user_id\":$UID_,\"group_id\":$SID}" >/dev/null
j -X DELETE "$API/admin/api/users/$UID_" -H "$A" >/dev/null
j -X DELETE "$API/admin/api/devices/$DEV" -H "$A" >/dev/null
j -X DELETE "$API/admin/api/groups/$SID" -H "$A" >/dev/null
must "grupo removido" "$(j "$API/admin/api/groups" -H "$A")" "map(select(.id==$SID)) | length == 0"
echo; echo "CONSOLE OK"
