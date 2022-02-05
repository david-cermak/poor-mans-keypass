# shellcheck disable=SC2006
CA_CRT=`cat ../keys/ca.crt | tr '\n' '*'`
SERVER_CRT=`cat ../keys/server.crt | tr '\n' '*'`
SERVER_KEY=`cat ../keys/server.key | tr '\n' '*'`
CLIENT_CRT=`cat ../keys/client.crt | tr '\n' '*'`
CLIENT_KEY=`cat ../keys/client.key | tr '\n' '*'`
MASTER_KEY=`cat ../keys/master.key | tr '\n' '*'`
MbedTLS_DIR=~/repos/mbedtls/build

export CA_CRT
export SERVER_KEY
export SERVER_CRT
export CLIENT_KEY
export CLIENT_CRT
export MASTER_KEY
export MbedTLS_DIR