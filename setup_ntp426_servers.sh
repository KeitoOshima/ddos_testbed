#!/bin/bash

set -e

TARGET_FILE="${1:-ntp_targets.txt}"
TAP_CONFIG="${2:-tap_config.txt}"

NTPD="/usr/local/ntp426/bin/ntpd"

if [ ! -f "${TARGET_FILE}" ]; then
    echo "Target file not found: ${TARGET_FILE}"
    exit 1
fi

if [ ! -f "${TAP_CONFIG}" ]; then
    echo "Tap config not found: ${TAP_CONFIG}"
    exit 1
fi


echo "======================================"
echo "NTP 4.2.6 server setup"
echo "Target file : ${TARGET_FILE}"
echo "Tap config  : ${TAP_CONFIG}"
echo "======================================"


while read -r ASN
do

    # 空行を無視
    [ -z "${ASN}" ] && continue

    # コメント行を無視
    [[ "${ASN}" =~ ^# ]] && continue


    # ======================================
    # tap_config.txt からAS情報取得
    # ======================================

    LINE=$(awk -v asn="${ASN}" '$1 == asn {print; exit}' "${TAP_CONFIG}")

    if [ -z "${LINE}" ]; then
        echo
        echo "WARNING: AS${ASN} was not found in ${TAP_CONFIG}"
        continue
    fi


    read -r \
        CONFIG_ASN \
        CONTAINER \
        CONTAINER_IP \
        GATEWAY <<< "${LINE}"


    #
    # 1.11.0.3/16
    #     ↓
    # 1.11.0.3
    #
    NTP_IP="${CONTAINER_IP%%/*}"


    echo
    echo "--------------------------------------"
    echo "AS        : ${ASN}"
    echo "Container : ${CONTAINER}"
    echo "NTP IP    : ${NTP_IP}"
    echo "Gateway   : ${GATEWAY}"
    echo "--------------------------------------"


    # ======================================
    # Container確認
    # ======================================

    if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
        echo "ERROR: Container '${CONTAINER}' does not exist."
        continue
    fi


    if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER}")" != "true" ]; then
        echo "ERROR: Container '${CONTAINER}' is not running."
        continue
    fi


    # ======================================
    # NTP 4.2.6確認
    # ======================================

    if ! docker exec "${CONTAINER}" \
        test -x "${NTPD}"
    then
        echo "ERROR: NTP 4.2.6 was not found:"
        echo "       ${NTPD}"
        continue
    fi


    echo "[NTP version]"

    docker exec "${CONTAINER}" \
        "${NTPD}" --version



    # ======================================
    # ntp.conf作成
    # ======================================

    docker exec "${CONTAINER}" sh -c "
cat > /tmp/ntp.conf << EOF
driftfile /tmp/ntp.drift

server 127.127.1.0
fudge 127.127.1.0 stratum 8

interface ignore wildcard
interface listen ${NTP_IP}

restrict default
restrict 127.0.0.1
EOF
"


    # ======================================
    # 以前のntpdを停止
    # ======================================

    docker exec "${CONTAINER}" \
        sh -c 'pkill ntpd 2>/dev/null || true'


    # ======================================
    # NTP 4.2.6起動
    # ======================================

    docker exec -d "${CONTAINER}" \
        "${NTPD}" \
        -n \
        -c /tmp/ntp.conf


    sleep 1


    # ======================================
    # 起動確認
    # ======================================

    echo
    echo "[Process]"

    docker exec "${CONTAINER}" \
        sh -c "ps aux | grep '[n]tpd' || true"


    echo
    echo "[UDP 123]"

    docker exec "${CONTAINER}" \
        sh -c "ss -lunp | grep ':123' || true"


    echo
    echo "[ntp.conf]"

    docker exec "${CONTAINER}" \
        cat /tmp/ntp.conf


    echo
    echo "AS${ASN}: NTP 4.2.6 started."

done < "${TARGET_FILE}"


echo
echo "======================================"
echo "All NTP 4.2.6 servers configured."
echo "======================================"
