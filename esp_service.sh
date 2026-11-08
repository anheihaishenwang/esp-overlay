#!/system/bin/sh
# ESP Service: 实体扫描 + Socket 服务

MODDIR="/data/adb/modules/hw_viewheight_ui"
ESP_DIR="$MODDIR/esp_scripts"
SOCKET_DIR="/data/local/tmp/esp_data"
LOG_FILE="$SOCKET_DIR/esp_service.log"

mkdir -p "$SOCKET_DIR"
: > "$LOG_FILE"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# 查找 python3
PYTHON=$(which python3)
[ -z "$PYTHON" ] && PYTHON="/system/bin/python3"
[ -x "$PYTHON" ] || PYTHON="/data/local/tmp/python3"
[ -x "$PYTHON" ] || { log "[!] python3 not found"; exit 1; }

log "╔══════════════════════════════════════╗"
log "║   ESP Entity Scanner v1.0           ║"
log "║   Read-only entity detection        ║"
log "╚══════════════════════════════════════╝"

# 启动 Python 扫描器
cd "$ESP_DIR"
log "[+] Starting ESP scanner on PID $$"
exec "$PYTHON" esp_scanner.py >> "$LOG_FILE" 2>&1
