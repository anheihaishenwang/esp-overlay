#!/system/bin/sh
# KernelSU Module: 王者荣耀视野高度修改 + ESP v6.4
# 双引擎：Native Injector + Python Scanner + ESP Entity Reader

MODDIR="/data/adb/modules/hw_viewheight_ui"
CONFIG_DIR="/data/local/tmp/view_height"
ESP_DIR="/data/local/tmp/esp_data"
COMMAND_FILE="$CONFIG_DIR/command.txt"
LOG_FILE="$CONFIG_DIR/inject.log"
ESP_LOG="$ESP_DIR/esp_service.log"

HEIGHT=20; DISTANCE=8; FOV=60; RENDER=4; MODE="manual"
ESP_ENABLED=1

read_config() {
    [ -f "$CONFIG_DIR/config.txt" ] && {
        HEIGHT=$(grep "^view_height=" "$CONFIG_DIR/config.txt" | cut -d= -f2); [ -z "$HEIGHT" ] && HEIGHT=20
        DISTANCE=$(grep "^view_distance=" "$CONFIG_DIR/config.txt" | cut -d= -f2); [ -z "$DISTANCE" ] && DISTANCE=8
        FOV=$(grep "^fov=" "$CONFIG_DIR/config.txt" | cut -d= -f2); [ -z "$FOV" ] && FOV=60
        RENDER=$(grep "^render_distance=" "$CONFIG_DIR/config.txt" | cut -d= -f2); [ -z "$RENDER" ] && RENDER=4
        MODE=$(grep "^exec_mode=" "$CONFIG_DIR/config.txt" | cut -d= -f2); [ -z "$MODE" ] && MODE="manual"
        ESP_ENABLED=$(grep "^esp_enabled=" "$CONFIG_DIR/config.txt" | cut -d= -f2); [ -z "$ESP_ENABLED" ] && ESP_ENABLED=1
    }
}

write_config() {
    mkdir -p "$CONFIG_DIR" 2>/dev/null
    echo "view_height=$HEIGHT" > "$CONFIG_DIR/config.txt"
    echo "view_distance=$DISTANCE" >> "$CONFIG_DIR/config.txt"
    echo "fov=$FOV" >> "$CONFIG_DIR/config.txt"
    echo "render_distance=$RENDER" >> "$CONFIG_DIR/config.txt"
    echo "exec_mode=$MODE" >> "$CONFIG_DIR/config.txt"
    echo "esp_enabled=$ESP_ENABLED" >> "$CONFIG_DIR/config.txt"
}

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

process_commands() {
    while [ -f "$COMMAND_FILE" ]; do
        CMD=$(cat "$COMMAND_FILE" 2>/dev/null); rm -f "$COMMAND_FILE"
        CMD_TYPE=$(echo "$CMD" | grep -o '"cmd"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
        CMD_VAL=$(echo "$CMD" | grep -o '"val"[[:space:]]*:[[:space:]]*[0-9.]*' | cut -d':' -f2 | tr -d ' ')
        case "$CMD_TYPE" in
            "set_height") [ -n "$CMD_VAL" ] && { HEIGHT=$CMD_VAL; write_config; log "[UI] Height=$HEIGHT"; [ "$MODE" = "manual" ] && pidof com.tencent.tmgp.sgame >/dev/null && inject; };;
            "set_mode") [ "$CMD_VAL" = "manual" -o "$CMD_VAL" = "auto" ] && { MODE=$CMD_VAL; write_config; log "[UI] Mode=$MODE"; };;
            "set_esp") [ "$CMD_VAL" = "0" -o "$CMD_VAL" = "1" ] && { ESP_ENABLED=$CMD_VAL; write_config; log "[UI] ESP=$ESP_ENABLED"; };;
            "get_status") echo "height=$HEIGHT,mode=$MODE,esp=$ESP_ENABLED" > "$CONFIG_DIR/status.txt";;
        esac
    done
}

inject_native() {
    local PID=$(pidof com.tencent.tmgp.sgame 2>/dev/null)
    [ -z "$PID" ] && { log "[!] Game not running"; return 1; }
    [ -x "$MODDIR/injector" ] || { log "[!] Injector binary not found"; return 1; }
    
    log "[+] Native Injector: PID=$PID Height=${HEIGHT}m"
    "$MODDIR/injector" "$HEIGHT" >> "$LOG_FILE" 2>&1
    local ret=$?
    [ $ret -eq 0 ] && log "[+] Native injection SUCCESS" || log "[!] Native injection FAILED (code=$ret)"
    return $ret
}

inject_python() {
    local PID=$(pidof com.tencent.tmgp.sgame 2>/dev/null)
    [ -z "$PID" ] && { log "[!] Game not running"; return 1; }
    
    log "[+] Python Scanner: PID=$PID Height=${HEIGHT}m FOV=$FOV Dist=$DISTANCE"

    python3 << PYEOF
import struct, sys, os

pid = $PID
target_height = float($HEIGHT)
target_fov = float($FOV)
target_dist = float($DISTANCE)

print(f"[*] Target: height={target_height} fov={target_fov} dist={target_dist}")

ranges = []
try:
    with open(f'/proc/{pid}/maps', 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 5: continue
            addr_range, perms, offset, dev, inode = parts[0], parts[1], parts[2], parts[3], parts[4]
            path = ' '.join(parts[5:]) if len(parts) > 5 else ''
            if 'libUnity.so' not in path: continue
            if 'r' not in perms or 'w' not in perms: continue
            start, end = [int(x, 16) for x in addr_range.split('-')]
            size = end - start
            if size < 4096 or size > 200*1024*1024: continue
            ranges.append((start, end, size, path))
except Exception as e:
    print(f"[!] maps error: {e}"); sys.exit(1)

if not ranges:
    print("[!] No libUnity.so RW regions found")
    sys.exit(1)

print(f"[*] Found {len(ranges)} libUnity.so RW regions")

candidates = []
for start, end, size, path in ranges:
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(start)
            chunk_size = min(size, 50*1024*1024)
            data = f.read(chunk_size)
        for i in range(0, len(data)-4, 4):
            try:
                val = struct.unpack('<f', data[i:i+4])[0]
                if 55.0 < val < 65.0:
                    candidates.append((start+i, val, 'fov', size))
                elif 10.0 < val < 55.0:
                    candidates.append((start+i, val, 'height', size))
                elif 0.1 < val < 20.0 and abs(val - round(val)) < 0.01:
                    candidates.append((start+i, val, 'dist', size))
            except: pass
    except: continue

print(f"[*] Total candidates: {len(candidates)}")
if not candidates:
    print("[!] No candidates found")
    sys.exit(1)

candidates.sort(key=lambda x: x[3], reverse=True)

height_written = fov_written = dist_written = 0
height_addrs = []
fov_addrs = []
dist_addrs = []

for addr, old_val, typ, sz in candidates:
    try:
        with open(f'/proc/{pid}/mem', 'wb') as f:
            f.seek(addr)
            if typ == 'height' and height_written < 50:
                f.write(struct.pack('<f', target_height))
                height_written += 1
                height_addrs.append((addr, old_val))
            elif typ == 'fov' and fov_written < 30:
                f.write(struct.pack('<f', target_fov))
                fov_written += 1
                fov_addrs.append((addr, old_val))
            elif typ == 'dist' and dist_written < 30:
                f.write(struct.pack('<f', target_dist))
                dist_written += 1
                dist_addrs.append((addr, old_val))
    except: pass

print(f"[+] Written: height={height_written} fov={fov_written} dist={dist_written}")

verified = 0
for addr, old in (height_addrs + fov_addrs + dist_addrs)[:15]:
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(addr)
            new = struct.unpack('<f', f.read(4))[0]
        if abs(new - (target_height if abs(old-target_height)>abs(old-target_fov) else target_fov)) < 0.5:
            verified += 1
            print(f"  [OK] 0x{addr:016x}: {old:.2f} -> {new:.2f}")
    except: pass

print(f"[+] Verified: {verified}/15")
print(f"[+] DONE: Height={target_height}m FOV={target_fov} Dist={target_dist}")
PYEOF
}

inject() {
    if inject_native; then
        return 0
    fi
    log "[!] Native failed, fallback to Python scanner..."
    inject_python
}

# ESP 服务管理
start_esp() {
    [ $ESP_ENABLED -eq 1 ] || return 0
    mkdir -p "$ESP_DIR"
    if [ -f "$MODDIR/esp_service.sh" ]; then
        log "[+] Starting ESP Service..."
        nohup sh "$MODDIR/esp_service.sh" >> "$ESP_LOG" 2>&1 &
        ESP_PID=$!
        echo $ESP_PID > "$ESP_DIR/esp.pid"
        log "[+] ESP Service started (PID=$ESP_PID)"
    else
        log "[!] ESP service script not found"
    fi
}

stop_esp() {
    [ -f "$ESP_DIR/esp.pid" ] && {
        kill $(cat "$ESP_DIR/esp.pid") 2>/dev/null
        rm -f "$ESP_DIR/esp.pid"
        log "[+] ESP Service stopped"
    }
}

wait_game() {
    local max=120 w=0
    while [ $w -lt $max ]; do
        pidof com.tencent.tmgp.sgame >/dev/null 2>&1 && return 0
        sleep 2; w=$((w+2))
    done; return 1
}

read_config
write_config
mkdir -p "$CONFIG_DIR" "$ESP_DIR"
: > "$LOG_FILE"
: > "$ESP_LOG"

log "╔═══════════════════════════════════════════╗"
log "║   王者荣耀视野高度修改 + ESP v6.4        ║"
log "║   Native Injector + Python + ESP Reader  ║"
log "║   作者: 暗黑海神王                        ║"
log "╚══════════════════════════════════════════╝"
log "[+] Config: H=${HEIGHT} D=${DISTANCE} FOV=${FOV} R=${RENDER} Mode=$MODE ESP=$ESP_ENABLED"

# 启动 ESP 服务
start_esp

# 后台命令处理
( while true; do process_commands; sleep 0.5; done ) &
CMD_PID=$!

# 主循环
while true; do
    if wait_game; then
        if [ "$MODE" = "auto" ]; then
            log "[AUTO] Game started, injecting..."
            inject
        else
            log "[MANUAL] Game running, waiting for UI command..."
        fi
        while pidof com.tencent.tmgp.sgame >/dev/null 2>&1; do
            process_commands; sleep 5
        done
        log "[+] Game exited"
    fi
    process_commands; sleep 5
done

kill $CMD_PID 2>/dev/null
stop_esp
