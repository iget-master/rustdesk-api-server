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

echo "== IP na LAN pelo heartbeat"
devs() { j "$API/admin/api/devices?group=$SID" -H "$A"; }
hb_ip() { j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":0${1:+,\"lan_ip\":\"$1\"}}" >/dev/null; }
hb_ip 192.168.15.42
must "console mostra o IP da LAN" "$(devs)" "any(.[]; .id==\"$DEV\" and .lan_ip==\"192.168.15.42\")"
must "busca por IP encontra a máquina" "$(j "$API/admin/api/devices?q=192.168.15" -H "$A")" "any(.[]; .id==\"$DEV\")"
hb_ip ""
must "heartbeat sem IP preserva o último" "$(devs)" "any(.[]; .id==\"$DEV\" and .lan_ip==\"192.168.15.42\")"
hb_ip 192.168.15.77
must "IP novo substitui o anterior" "$(devs)" "any(.[]; .id==\"$DEV\" and .lan_ip==\"192.168.15.77\")"

echo "== cliente personalizado: senha pelo heartbeat"
hb() { j -X POST "$API/api/heartbeat" -d "{\"id\":\"$1\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":0,\"enroll_token\":\"$2\",\"password_tag\":\"$3\"}"; }
HB=$(hb "$DEV" "$ENROLL" "")
must "heartbeat entrega a senha do grupo" "$HB" ".password==\"$PASS\" and (.password_tag|length)==16"
PTAG=$(echo "$HB" | jq -r .password_tag)
must "com a tag certa não reenvia" "$(hb "$DEV" "$ENROLL" "$PTAG")" 'has("password")|not'
must "console mostra senha sincronizada" "$(j "$API/admin/api/devices?group=$SID" -H "$A")" "map(select(.id==\"$DEV\")) | .[0].sync_client==true and .[0].password_synced==true"
must "token inválido não matricula máquina fora de grupo" "$(hb "${DEV}8" "nope" "")" 'has("password")|not'
DEV2=${DEV}9
must "máquina nova com token entra no grupo sozinha" "$(hb "$DEV2" "$ENROLL" "")" ".password==\"$PASS\""
must "console lista a máquina nova no grupo" "$(j "$API/admin/api/devices?group=$SID" -H "$A")" "map(select(.id==\"$DEV2\")) | length == 1"

echo "== matrícula pelo console (sem token): o grupo empurra a senha"
hb_plain() { j -X POST "$API/api/heartbeat" -d "{\"id\":\"$1\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":0}"; }
DEV3=${DEV}7
must "máquina fora de grupo não recebe senha" "$(hb_plain "$DEV3")" 'has("password")|not'
must "fora de grupo aparece como manual" "$(j "$API/admin/api/devices?q=$DEV3" -H "$A")" "any(.[]; .id==\"$DEV3\" and .sync_client==false)"
j -X PUT "$API/admin/api/devices/$DEV3" -H "$A" -d "{\"group_id\":$SID}" >/dev/null
must "atribuída ao grupo pelo console, o heartbeat entrega a senha" "$(hb_plain "$DEV3")" ".password==\"$PASS\" and (.password_tag|length)==16"
must "entregue uma vez, não reenvia no heartbeat seguinte" "$(hb_plain "$DEV3")" 'has("password")|not'
must "console mostra sincronizada mesmo sem token" "$(j "$API/admin/api/devices?group=$SID" -H "$A")" "map(select(.id==\"$DEV3\")) | .[0].sync_client==true and .[0].password_synced==true"

echo "== auto-update pelo heartbeat"
hb_ver() { j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":$1,\"modified_at\":0}"; }
# sem client_version configurado: nada de update
must "sem versão publicada não manda update" "$(hb_ver 1004090)" 'has("update")|not'
j -X PUT "$API/admin/api/settings" -H "$A" -d '{"client_version":"1.4.10","download_url":"http://api.example.com:21114/downloads/RustdeskOlirio-1.4.10-x86_64.exe"}' >/dev/null
# cliente em 1.4.9 (1004090) < 1.4.10 (1004100): recebe update com token do grupo
must "cliente mais antigo recebe update" "$(hb_ver 1004090)" '.update.version=="1.4.10" and (.update.url|test("RustdeskOlirio-1.4.10")) and (.update.token|length)>20'
# cliente já na versão nova: nada
must "cliente já atualizado não recebe update" "$(hb_ver 1004100)" 'has("update")|not'
# máquina fora de grupo não recebe update (não é gerenciada)
must "máquina fora de grupo não recebe update" "$(j -X POST "$API/api/heartbeat" -d '{"id":"777000777","uuid":"dGVzdA==","ver":1004090,"modified_at":0}')" 'has("update")|not'
# rebuild nosso sobre a MESMA versão oficial: 1.4.9-8 > 1.4.9 (1004098 > 1004090).
# Sem o sufixo do build, os dois empatam e o update nunca sairia.
j -X PUT "$API/admin/api/settings" -H "$A" -d '{"client_version":"1.4.9-8","download_url":"http://api.example.com:21114/downloads/RustdeskOlirio-1.4.9-8-x86_64.exe"}' >/dev/null
must "rebuild da mesma versão oficial dispara update" "$(hb_ver 1004090)" '.update.version=="1.4.9-8"'
must "máquina já no build novo não recebe update" "$(hb_ver 1004098)" 'has("update")|not'

echo "== instaladores hospedados na API"
FAKE=/tmp/rdapi-fake-installer.bin; printf 'fake-installer' > "$FAKE"
must "upload" "$(curl -sS -X PUT "$API/admin/api/downloads/Fake-1.4.11-x86_64.exe?use=1" -H "$A" -H 'Content-Type: application/octet-stream' --data-binary "@$FAKE")" '.name=="Fake-1.4.11-x86_64.exe" and .size==14 and .used==true'
must "use=1 apontou o script para o arquivo" "$(j "$API/admin/api/settings" -H "$A")" '.download_url=="http://api.example.com:21114/downloads/Fake-1.4.11-x86_64.exe"'
must "use=1 gravou a versão publicada (do nome)" "$(j "$API/admin/api/settings" -H "$A")" '.client_version=="1.4.11"'
# nome com o número do nosso build: a versão publicada tem que incluir o sufixo
curl -sS -X PUT "$API/admin/api/downloads/Fake-1.4.11-9-x86_64.exe?use=1" -H "$A" -H 'Content-Type: application/octet-stream' --data-binary "@$FAKE" >/dev/null
must "use=1 lê a versão com o número do build" "$(j "$API/admin/api/settings" -H "$A")" '.client_version=="1.4.11-9"'
must_code "apaga o instalador com sufixo" "$(code -X DELETE "$API/admin/api/downloads/Fake-1.4.11-9-x86_64.exe" -H "$A")" 200
must "lista" "$(j "$API/admin/api/downloads" -H "$A")" 'map(select(.name=="Fake-1.4.11-x86_64.exe")) | length==1'
must_code "download sem token" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe")" 401
must_code "download com token do grupo" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe" -H "X-Enroll-Token: $ENROLL")" 200
must_code "download com token na query" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe?token=$ENROLL")" 200
must_code "download com sessão de admin" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe" -H "$A")" 200
[ "$(curl -sS "$API/downloads/Fake-1.4.11-x86_64.exe" -H "X-Enroll-Token: $ENROLL")" = "fake-installer" ] && echo "ok  conteúdo íntegro" || die "conteúdo do download"
must_code "nome com caminho é recusado" "$(code "$API/downloads/..%2Fetc%2Fpasswd" -H "X-Enroll-Token: $ENROLL")" 404

echo "== token de download de instaladores (sem poder de matrícula)"
IT=$(j "$API/admin/api/settings" -H "$A" | jq -r .installer_token)
must "settings expõe o token de download" "$(j "$API/admin/api/settings" -H "$A")" '(.installer_token|length) > 20'
must_code "download com o token de instaladores" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe?token=$IT")" 200
must_code "token de instaladores errado é recusado" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe?token=zzzzz")" 401
must_code "token de instaladores não matricula" "$(code -X POST "$API/api/enroll" -d "{\"token\":\"$IT\",\"id\":\"888000888\"}")" 403
NEWIT=$(j -X POST "$API/admin/api/installer-token/rotate" -H "$A" | jq -r .installer_token)
must "rotate devolve token novo" "$(printf '{"a":"%s","b":"%s"}' "$NEWIT" "$IT")" '.a != .b and (.a|length) > 20'
must_code "token antigo para de funcionar" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe?token=$IT")" 401
must_code "token novo funciona" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe?token=$NEWIT")" 200
grep -q "X-Enroll-Token" <<< "$(j "$API/admin/api/groups/$SID/install-script?os=windows" -H "$A")" && echo "ok  script baixa com o token de matrícula" || die "script sem X-Enroll-Token"
must_code "apagar" "$(code -X DELETE "$API/admin/api/downloads/Fake-1.4.11-x86_64.exe" -H "$A")" 200
must_code "apagado some" "$(code "$API/downloads/Fake-1.4.11-x86_64.exe" -H "X-Enroll-Token: $ENROLL")" 404

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

echo "== autorização das conexões (hbbs -> API)"
SECRET=$(j "$API/admin/api/settings" -H "$A" | jq -r .hbbs_secret)
[ ${#SECRET} -ge 32 ] || die "segredo do hbbs: $SECRET"
authz() { j -X POST "$API/api/internal/authorize" -H "X-Hbbs-Secret: $SECRET" -d "$1"; }
must_code "sem o segredo" "$(code -X POST "$API/api/internal/authorize" -d "{\"token\":\"\",\"peer_id\":\"$DEV\"}")" 401
must "anônimo permitido enquanto o grupo não exige login" "$(authz "{\"token\":\"\",\"peer_id\":\"$DEV\"}")" '.allow==true'
must "grupo passa a exigir login" "$(j -X PUT "$API/admin/api/groups/$SID" -H "$A" -d '{"require_login":true}')" '.require_login==true'
must "anônimo recusado" "$(authz "{\"token\":\"\",\"peer_id\":\"$DEV\",\"from\":\"203.0.113.9\"}")" '.allow==false and (.reason|length) > 0'
must "token inválido recusado" "$(authz "{\"token\":\"nope\",\"peer_id\":\"$DEV\"}")" '.allow==false'
must "externo com acesso ao grupo permitido" "$(authz "{\"token\":\"$EXT_TOKEN\",\"peer_id\":\"$DEV\"}")" ".allow==true and .user==\"$EXT\""
must "externo recusado em máquina fora dos seus grupos" "$(authz "{\"token\":\"$EXT_TOKEN\",\"peer_id\":\"000000001\"}")" '.allow==false'
must "administrador permitido" "$(authz "{\"token\":\"$TOKEN\",\"peer_id\":\"$DEV\"}")" '.allow==true and .user=="'"$RD_USER"'"'
must "máquina desconhecida sem política" "$(authz "{\"token\":\"\",\"peer_id\":\"000000001\"}")" '.allow==true'
must "política global: só máquinas em grupo" "$(j -X PUT "$API/admin/api/settings" -H "$A" -d '{"require_group":"1"}')" '.require_group=="1"'
must "desconhecida recusada com a política" "$(authz "{\"token\":\"$TOKEN\",\"peer_id\":\"000000001\"}")" '.allow==false and (.reason|test("cadastrado"))'
must "máquina do grupo continua liberada para o admin" "$(authz "{\"token\":\"$TOKEN\",\"peer_id\":\"$DEV\"}")" '.allow==true'
j -X PUT "$API/admin/api/settings" -H "$A" -d '{"require_group":"0"}' >/dev/null

echo "== relay: hbbr só pareia sessões anunciadas"
relay() { j -X POST "$API/api/internal/relay" -H "X-Hbbs-Secret: $SECRET" -d "$1"; }
must_code "relay sem o segredo" "$(code -X POST "$API/api/internal/relay" -d '{"op":"check","uuid":"u-1"}')" 401
must "sessão não anunciada é recusada" "$(relay '{"op":"check","uuid":"u-1","from":"203.0.113.9"}')" '.allow==false'
must "hbbs anuncia" "$(relay '{"op":"announce","uuid":"u-1"}')" '.ok==true'
must "sessão anunciada é liberada" "$(relay '{"op":"check","uuid":"u-1"}')" '.allow==true'
must "autorização de relay já anuncia a sessão" "$(authz "{\"token\":\"$TOKEN\",\"peer_id\":\"$DEV\",\"relay_uuid\":\"u-2\"}")" '.allow==true'
must "u-2 liberada no relay" "$(relay '{"op":"check","uuid":"u-2"}')" '.allow==true'
must "pedido recusado não anuncia" "$(authz "{\"token\":\"\",\"peer_id\":\"$DEV\",\"relay_uuid\":\"u-3\"}")" '.allow==false'
must "u-3 segue recusada" "$(relay '{"op":"check","uuid":"u-3"}')" '.allow==false'
must "recusa de relay na auditoria" "$(j "$API/admin/api/audit/denied?device=relay" -H "$A")" '.total >= 1 and (.data[0].reason|test("relay"))'
must "recusas ficam na auditoria" "$(j "$API/admin/api/audit/denied?device=$DEV" -H "$A")" '.total >= 2 and any(.data[]; .from_ip=="203.0.113.9")'

echo "== listagens do console"
for k in conn file alarm denied; do
  must "auditoria/$k responde" "$(j "$API/admin/api/audit/$k?group=$SID&limit=5" -H "$A")" 'has("total") and (.data|type)=="array"'
done
must "visão geral responde" "$(j "$API/admin/api/overview" -H "$A")" '.devices >= 1 and (.recent|type)=="array" and (.per_group|type)=="array"'

echo "== rotação de senha"
NEW=$(j -X POST "$API/admin/api/groups/$SID/rotate-password" -H "$A" | jq -r .password)
[ "$NEW" != "$PASS" ] && [ ${#NEW} -ge 8 ] || die "rotação de senha"
must "AB atualizado com a nova senha" "$(j -X POST "$API/api/ab/peers?current=1&pageSize=100&ab=$GUID" -H "$E" -H 'Content-Length: 0')" ".data[0].password==\"$NEW\""
j "$API/admin/api/groups/$SID/install-script?os=windows" -H "$A" | grep -q -- "--password '$NEW'" && echo "ok  script Windows traz a senha nova" || die "script Windows"
j "$API/admin/api/groups/$SID/install-script?os=linux" -H "$A" | grep -q "$ENROLL" && echo "ok  script Linux traz o token de matrícula" || die "script Linux"
must "heartbeat entrega a senha rotacionada" "$(hb "$DEV" "$ENROLL" "$PTAG")" ".password==\"$NEW\""
must "máquina do console (sem token) recebe a senha rotacionada" "$(hb_plain "$DEV3")" ".password==\"$NEW\""
must "console marca a senha como pendente" "$(j "$API/admin/api/devices?group=$SID" -H "$A")" "map(select(.id==\"$DEV\")) | .[0].password_synced==false"
must "settings aceita o cliente personalizado" "$(j -X PUT "$API/admin/api/settings" -H "$A" -d '{"client_app_name":"RustdeskOlirio"}')" '.client_app_name=="RustdeskOlirio"'
SCRIPT=$(j "$API/admin/api/groups/$SID/install-script?os=windows" -H "$A")
grep -q "Program Files\\\\RustdeskOlirio\\\\RustdeskOlirio.exe" <<< "$SCRIPT" && echo "ok  script instala o cliente personalizado" || die "script cliente personalizado"
grep -q -- "--option enroll-token '$ENROLL'" <<< "$SCRIPT" && echo "ok  script grava o token de matrícula" || die "script enroll-token"
grep -q "custom-rendezvous-server" <<< "$SCRIPT" && die "script do cliente personalizado não deve configurar servidor" || echo "ok  script não mexe no servidor (fixo no cliente)"
j -X PUT "$API/admin/api/settings" -H "$A" -d '{"client_app_name":""}' >/dev/null

echo "== derrubar sessão"
j -X POST "$API/admin/api/users/$UID_/logout" -H "$A" >/dev/null
must_code "sessão do externo encerrada" "$(code -X POST "$API/api/currentUser" -H "$E" -d '{}')" 401
must "hbbs passa a recusar o token derrubado" "$(authz "{\"token\":\"$EXT_TOKEN\",\"peer_id\":\"$DEV\"}")" '.allow==false and (.reason|test("sessão"))'

echo "== limpeza"
j -X DELETE "$API/admin/api/grants" -H "$A" -d "{\"user_id\":$UID_,\"group_id\":$SID}" >/dev/null
j -X DELETE "$API/admin/api/users/$UID_" -H "$A" >/dev/null
j -X DELETE "$API/admin/api/devices/$DEV" -H "$A" >/dev/null
j -X DELETE "$API/admin/api/devices/$DEV2" -H "$A" >/dev/null
j -X DELETE "$API/admin/api/groups/$SID" -H "$A" >/dev/null
must "grupo removido" "$(j "$API/admin/api/groups" -H "$A")" "map(select(.id==$SID)) | length == 0"
echo; echo "CONSOLE OK"
