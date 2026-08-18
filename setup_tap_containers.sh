#!/bin/bash

set -e

CONFIG_FILE="${1:-tap_config.txt}"

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Config file not found: ${CONFIG_FILE}"
    exit 1
fi

if [ "${EUID}" -ne 0 ]; then
    echo "Please run with sudo."
    exit 1
fi

echo "======================================"
echo "Docker <-> ns-3 TapBridge setup"
echo "Config: ${CONFIG_FILE}"
echo "======================================"

while read -r ASN CONTAINER CONTAINER_IP GATEWAY
do
    # 空行を無視
    [ -z "${ASN}" ] && continue

    # コメント行を無視
    [[ "${ASN}" =~ ^# ]] && continue

    TAP="tap-as${ASN}"
    BRIDGE="br-as${ASN}"

    VETH_HOST="vh-${ASN}"
    VETH_CONT="vc-${ASN}"

    echo
    echo "--------------------------------------"
    echo "AS           : ${ASN}"
    echo "container    : ${CONTAINER}"
    echo "container IP : ${CONTAINER_IP}"
    echo "gateway      : ${GATEWAY}"
    echo "tap          : ${TAP}"
    echo "bridge       : ${BRIDGE}"
    echo "--------------------------------------"

    # ======================================
    # Container確認
    # ======================================

    if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
        echo "ERROR: Docker container '${CONTAINER}' does not exist."
        exit 1
    fi

    PID=$(docker inspect -f '{{.State.Pid}}' "${CONTAINER}")

    if [ "${PID}" = "0" ]; then
        echo "ERROR: Container '${CONTAINER}' is not running."
        exit 1
    fi

    # ======================================
    # 既存host側設定削除
    # ======================================

    ip link del "${VETH_HOST}" 2>/dev/null || true
    ip link del "${TAP}" 2>/dev/null || true
    ip link del "${BRIDGE}" 2>/dev/null || true

    # ======================================
    # Linux bridge作成
    # ======================================

    ip link add name "${BRIDGE}" type bridge
    ip link set "${BRIDGE}" up

    # ======================================
    # TAP作成
    # ======================================

    ip tuntap add dev "${TAP}" mode tap
    ip link set "${TAP}" up
    ip link set "${TAP}" master "${BRIDGE}"

    # ======================================
    # veth pair作成
    # ======================================

    ip link add "${VETH_HOST}" type veth peer name "${VETH_CONT}"

    # host側vethをbridgeへ接続
    ip link set "${VETH_HOST}" master "${BRIDGE}"
    ip link set "${VETH_HOST}" up

    # ======================================
    # container namespaceへ移動
    # ======================================

    ip link set "${VETH_CONT}" netns "${PID}"

    # 前回作ったeth1が残っていれば削除
    nsenter -t "${PID}" -n \
        ip link del eth1 2>/dev/null || true

    # container側をeth1へrename
    nsenter -t "${PID}" -n \
        ip link set "${VETH_CONT}" name eth1

    nsenter -t "${PID}" -n \
        ip link set eth1 up

    # ======================================
    # container IP設定
    # ======================================

    nsenter -t "${PID}" -n \
        ip addr flush dev eth1

    nsenter -t "${PID}" -n \
        ip addr add "${CONTAINER_IP}" dev eth1

    # ======================================
    # default routeをns-3側へ
    # ======================================

    nsenter -t "${PID}" -n \
        ip route replace default via "${GATEWAY}" dev eth1

    # ======================================
    # 確認表示
    # ======================================

    echo
    echo "[Interface]"
    nsenter -t "${PID}" -n \
        ip -br addr show eth1

    echo
    echo "[Routes]"
    nsenter -t "${PID}" -n \
        ip route

    echo
    echo "[Route to gateway]"
    nsenter -t "${PID}" -n \
        ip route get "${GATEWAY}" || true

    echo
    echo "AS${ASN}: setup complete."

done < "${CONFIG_FILE}"

echo
echo "======================================"
echo "All configurations completed."
echo "======================================"
