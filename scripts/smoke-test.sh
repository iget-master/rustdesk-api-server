#!/usr/bin/env bash
# Exercita o contrato que o cliente RustDesk usa, contra um servidor já no ar.
#   API=http://127.0.0.1:21114 RD_USER=admin RD_PASS=senha ./scripts/smoke-test.sh
set -euo pipefail

API=${API:-http://127.0.0.1:21114}
RD_USER=${RD_USER:-admin}
RD_PASS=${RD_PASS:?defina RD_PASS}
DEV=${DEV:-123456789}
SID=1234567890

j() { curl -sS -H 'Content-Type: application/json' "$@"; }
expect_status() { # expect_status <código> <descrição> curl-args...
  local want=$1 what=$2; shift 2
  local got; got=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' "$@")
  if [ "$got" != "$want" ]; then echo "FALHOU: $what -> HTTP $got (esperado $want)"; exit 1; fi
  echo "ok  $what -> $got"
}
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }

echo "== login-options"; j "$API/api/login-options"; echo
expect_status 200 "HEAD login-options (sonda TLS)" -I "$API/api/login-options"

echo "== login"
TOKEN=$(j -X POST "$API/api/login" -d "{\"username\":\"$RD_USER\",\"password\":\"$RD_PASS\",\"id\":\"111\",\"uuid\":\"dGVzdA==\",\"autoLogin\":true,\"type\":\"account\",\"deviceInfo\":{\"os\":\"linux\",\"type\":\"client\",\"name\":\"smoke\"}}" | field access_token)
[ -n "$TOKEN" ] || { echo "login falhou"; exit 1; }
A="Authorization: Bearer $TOKEN"
expect_status 401 "login com senha errada" -X POST "$API/api/login" -d "{\"username\":\"$RD_USER\",\"password\":\"errada\",\"type\":\"account\"}"

echo "== currentUser"; j -X POST "$API/api/currentUser" -H "$A" -d '{"id":"111","uuid":"dGVzdA=="}'; echo
expect_status 401 "currentUser sem token" -X POST "$API/api/currentUser" -d '{}'

echo "== address book"
GUID=$(j -X POST "$API/api/ab/personal" -H "$A" -H 'Content-Length: 0' | field guid)
[ -n "$GUID" ] || { echo "ab/personal falhou"; exit 1; }
echo "guid pessoal: $GUID"
j -X POST "$API/api/ab/settings" -H "$A" -H 'Content-Length: 0'; echo
expect_status 200 "tag add" -X POST "$API/api/ab/tag/add/$GUID" -H "$A" -d '{"name":"prod","color":4283215696}'
expect_status 400 "tag duplicada" -X POST "$API/api/ab/tag/add/$GUID" -H "$A" -d '{"name":"prod","color":1}'
expect_status 200 "peer add" -X POST "$API/api/ab/peer/add/$GUID" -H "$A" -d "{\"id\":\"$DEV\",\"username\":\"alice\",\"hostname\":\"PC-01\",\"platform\":\"Windows\",\"alias\":\"Servidor\",\"tags\":[\"prod\"],\"hash\":\"abc\"}"
expect_status 200 "peer update alias" -X PUT "$API/api/ab/peer/update/$GUID" -H "$A" -d "{\"id\":\"$DEV\",\"alias\":\"Servidor de arquivos\"}"
expect_status 200 "peer update tags" -X PUT "$API/api/ab/peer/update/$GUID" -H "$A" -d "{\"id\":\"$DEV\",\"tags\":[\"prod\"]}"
expect_status 200 "tag rename" -X PUT "$API/api/ab/tag/rename/$GUID" -H "$A" -d '{"old":"prod","new":"producao"}'
expect_status 200 "tag color" -X PUT "$API/api/ab/tag/update/$GUID" -H "$A" -d '{"name":"producao","color":4294940672}'
echo "-- peers:"; j -X POST "$API/api/ab/peers?current=1&pageSize=100&ab=$GUID" -H "$A" -H 'Content-Length: 0'; echo
echo "-- tags:";  j -X POST "$API/api/ab/tags/$GUID" -H "$A" -H 'Content-Length: 0'; echo
echo "-- shared profiles:"; j -X POST "$API/api/ab/shared/profiles?current=1&pageSize=100" -H "$A" -H 'Content-Length: 0'; echo

echo "== heartbeat / sysinfo"
echo "-- heartbeat (dispositivo desconhecido, deve pedir sysinfo):"
j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"modified_at\":0}"; echo
echo "-- sysinfo:"
j -X POST "$API/api/sysinfo" -d "{\"cpu\":\"i7, 8/4 cores\",\"memory\":\"16GB\",\"os\":\"windows / Windows 11 Pro - 10.0.26200\",\"hostname\":\"PC-01\",\"username\":\"alice\",\"version\":\"1.4.2\",\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\"}"; echo
echo "-- heartbeat com conexão ativa:"
j -X POST "$API/api/heartbeat" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"ver\":1004020,\"conns\":[3],\"modified_at\":0}"; echo

echo "== aba grupo"
j "$API/api/peers?current=1&pageSize=100&accessible=&status=1" -H "$A"; echo
j "$API/api/users?current=1&pageSize=100&accessible=&status=1" -H "$A"; echo
j "$API/api/device-group/accessible?current=1&pageSize=100" -H "$A"; echo

echo "== auditoria"
expect_status 200 "audit conn new" -X POST "$API/api/audit/conn" -d "{\"action\":\"new\",\"ip\":\"203.0.113.5\",\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"conn_id\":3,\"session_id\":$SID,\"nonce\":\"n1-$RANDOM\"}"
expect_status 200 "audit conn authed" -X POST "$API/api/audit/conn" -d "{\"peer\":[\"987654321\",\"Bob\"],\"type\":0,\"primary_auth\":3,\"two_factor\":1,\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"conn_id\":3,\"session_id\":$SID,\"nonce\":\"n2-$RANDOM\"}"
NONCE="dup-$RANDOM"
expect_status 200 "audit conn (1ª vez)" -X POST "$API/api/audit/conn" -d "{\"action\":\"new\",\"ip\":\"1.2.3.4\",\"id\":\"$DEV\",\"uuid\":\"x\",\"conn_id\":4,\"session_id\":42,\"nonce\":\"$NONCE\"}"
expect_status 200 "audit conn (nonce repetido)" -X POST "$API/api/audit/conn" -d "{\"action\":\"new\",\"ip\":\"1.2.3.4\",\"id\":\"$DEV\",\"uuid\":\"x\",\"conn_id\":4,\"session_id\":42,\"nonce\":\"$NONCE\"}"
AG=$(j "$API/api/audit/conn/active?id=$DEV&session_id=$SID&conn_type=0" -H "$A")
echo "guid da auditoria: $AG"
[ "$AG" != '""' ] || { echo "audit/conn/active não achou o registro"; exit 1; }
expect_status 200 "nota via PUT /api/audit" -X PUT "$API/api/audit" -H "$A" -d "{\"guid\":$AG,\"note\":\"troca de impressora\"}"
expect_status 200 "nota do lado controlador" -X POST "$API/api/audit/conn" -d "{\"id\":\"$DEV\",\"session_id\":$SID,\"note\":\"nota do controlador\"}"
expect_status 200 "audit conn close" -X POST "$API/api/audit/conn" -d "{\"action\":\"close\",\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"conn_id\":3,\"session_id\":$SID,\"nonce\":\"n3-$RANDOM\"}"
expect_status 200 "audit file" -X POST "$API/api/audit/file" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"peer_id\":\"987654321\",\"conn_id\":3,\"type\":0,\"path\":\"C:/x\",\"is_file\":false,\"info\":\"{\\\"num\\\":1}\",\"nonce\":\"n4-$RANDOM\"}"
expect_status 200 "audit alarm" -X POST "$API/api/audit/alarm" -d "{\"id\":\"$DEV\",\"uuid\":\"dGVzdA==\",\"typ\":0,\"info\":\"{}\",\"conn_id\":3,\"nonce\":\"n5-$RANDOM\"}"

echo "== outros"
j -X POST "$API/api/switch-grant" -d '{"id":"1"}'; echo
j -X POST "$API/api/devices/deploy" -H "$A" -d '{"id":"1","uuid":"x","pk":"y"}'; echo
expect_status 404 "legado /api/ab/get" -X POST "$API/api/ab/get" -H "$A" -d '{}'

echo "== limpeza"
expect_status 200 "peer delete" -X DELETE "$API/api/ab/peer/$GUID" -H "$A" -d "[\"$DEV\"]"
expect_status 200 "tag delete" -X DELETE "$API/api/ab/tag/$GUID" -H "$A" -d '["producao"]'
expect_status 200 "logout" -X POST "$API/api/logout" -H "$A" -d '{"id":"111","uuid":"dGVzdA=="}'
expect_status 401 "token após logout" -X POST "$API/api/currentUser" -H "$A" -d '{}'

echo; echo "TUDO OK"
