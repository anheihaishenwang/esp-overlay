#!/usr/bin/env python3
# ESP Scanner: 读取王者荣耀实体信息 (位置、血量、类型)
# 只读不写，通过 Unix Socket 发送给绘制覆盖层

import struct
import sys
import os
import time
import socket
import json
import threading
from ctypes import CDLL, c_int, c_void_p, c_char_p, c_size_t, c_long

TARGET_PKG = "com.tencent.tmgp.sgame"
SOCKET_PATH = "/data/local/tmp/esp_data/esp.sock"
SCAN_INTERVAL = 0.05  # 20 FPS

# Unity/IL2CPP 常见偏移 (需根据实际版本调整)
ENTITY_OFFSETS = {
    'Actor': {
        'health': 0x18,
        'max_health': 0x1C,
        'team_id': 0x24,
        'position': 0x30,  # Vector3
        'name_ptr': 0x40,
    },
    'Hero': {
        'hero_id': 0x50,
        'level': 0x58,
    },
    'Monster': {
        'monster_id': 0x50,
        'camp_type': 0x58,
    },
    'Minion': {
        'minion_id': 0x50,
    }
}

class MemoryReader:
    def __init__(self, pid):
        self.pid = pid
        self.mem_fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        self.libc = CDLL("libc.so.6")
        
    def read_bytes(self, addr, size):
        try:
            os.lseek(self.mem_fd, addr, os.SEEK_SET)
            return os.read(self.mem_fd, size)
        except:
            return None
            
    def read_float(self, addr):
        data = self.read_bytes(addr, 4)
        if data and len(data) == 4:
            return struct.unpack('<f', data)[0]
        return None
        
    def read_int32(self, addr):
        data = self.read_bytes(addr, 4)
        if data and len(data) == 4:
            return struct.unpack('<i', data)[0]
        return None
        
    def read_int64(self, addr):
        data = self.read_bytes(addr, 8)
        if data and len(data) == 8:
            return struct.unpack('<q', data)[0]
        return None
        
    def read_vec3(self, addr):
        x = self.read_float(addr)
        y = self.read_float(addr + 4)
        z = self.read_float(addr + 8)
        if x is not None and y is not None and z is not None:
            return (x, y, z)
        return None
        
    def read_string(self, addr, max_len=64):
        try:
            # 先读指针
            str_ptr = self.read_int64(addr)
            if not str_ptr:
                return None
            data = self.read_bytes(str_ptr, max_len)
            if data:
                # Unity 字符串: 前 4 字节长度
                length = struct.unpack('<i', data[:4])[0]
                if 0 < length < max_len:
                    return data[4:4+length].decode('utf-8', errors='ignore')
        except:
            pass
        return None

    def close(self):
        os.close(self.mem_fd)


class EntityScanner:
    def __init__(self, pid):
        self.pid = pid
        self.reader = MemoryReader(pid)
        self.regions = []
        self.entity_list_addr = None
        
    def scan_unity_regions(self):
        """扫描 libUnity.so 和游戏堆区域"""
        self.regions = []
        try:
            with open(f"/proc/{self.pid}/maps", 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue
                    addr_range, perms, _, _, _ = parts[0], parts[1], parts[2], parts[3], parts[4]
                    path = ' '.join(parts[5:]) if len(parts) > 5 else ''
                    
                    # 关注区域: libUnity.so (rw), [anon] (rw, 大堆), [heap]
                    if ('libUnity.so' in path or '[anon]' in path or '[heap]' in path) and 'r' in perms and 'w' in perms:
                        start, end = [int(x, 16) for x in addr_range.split('-')]
                        size = end - start
                        if size >= 1024*1024:  # 至少 1MB
                            self.regions.append((start, end, size, path))
        except Exception as e:
            print(f"[!] Maps scan error: {e}")
            
        print(f"[*] Found {len(self.regions)} memory regions")
        return self.regions
        
    def find_entity_list(self):
        """寻找实体列表指针 (全局 GameObject 列表或 Actor 管理器)"""
        # 策略: 扫描特征模式 - 连续的指针数组，指向相似结构
        candidates = []
        
        for start, end, size, path in self.regions:
            if size > 200*1024*1024:  # 太大跳过
                continue
            try:
                data = self.reader.read_bytes(start, min(size, 50*1024*1024))
                if not data:
                    continue
                    
                # 扫描可能的实体列表头 (指针数组)
                # 特征: 连续的有效指针，指向的内存都在同一区域
                for i in range(0, len(data) - 8, 8):
                    try:
                        ptr = struct.unpack('<Q', data[i:i+8])[0]
                        # 检查指针合理性
                        if 0x700000000000 < ptr < 0x7FFFFFFFFFFF:  # 用户空间
                            # 验证指向的对象结构
                            obj_data = self.reader.read_bytes(ptr, 64)
                            if obj_data and self._looks_like_entity(obj_data):
                                candidates.append((ptr, start + i))
                    except:
                        continue
                        
                if candidates:
                    print(f"[*] Found {len(candidates)} entity candidates in {path}")
                    # 取第一个作为列表头
                    self.entity_list_addr = candidates[0][1]
                    break
                    
            except Exception as e:
                continue
                
        return self.entity_list_addr
        
    def _looks_like_entity(self, data):
        """启发式判断是否为实体对象"""
        if len(data) < 64:
            return False
        try:
            # 检查血量字段 (通常在 0x18, 值在 1-10000)
            health = struct.unpack('<f', data[0x18:0x1C])[0]
            max_hp = struct.unpack('<f', data[0x1C:0x20])[0]
            if not (0 < health <= max_hp <= 20000):
                return False
            # 检查位置向量
            x, y, z = struct.unpack('<fff', data[0x30:0x3C])
            if not (-50000 < x < 50000 and -50000 < z < 50000):
                return False
            # team_id 合理
            team = struct.unpack('<i', data[0x24:0x28])[0]
            if team < 0 or team > 10:
                return False
            return True
        except:
            return False
            
    def read_entities(self, max_entities=200):
        """读取实体列表"""
        entities = []
        if not self.entity_list_addr:
            self.find_entity_list()
        if not self.entity_list_addr:
            return entities
            
        try:
            # 读取列表头部 (假设是标准 List<T> 结构: _items 数组指针, _size, _version)
            list_data = self.reader.read_bytes(self.entity_list_addr, 32)
            if not list_data:
                return entities
                
            items_ptr = struct.unpack('<Q', list_data[0:8])[0]
            size = struct.unpack('<i', list_data[8:12])[0]
            
            if size <= 0 or size > max_entities:
                return entities
                
            # 读取数组指针
            array_data = self.reader.read_bytes(items_ptr, size * 8)
            if not array_data:
                return entities
                
            for i in range(size):
                try:
                    entity_ptr = struct.unpack('<Q', array_data[i*8:i*8+8])[0]
                    entity = self.read_entity(entity_ptr)
                    if entity:
                        entities.append(entity)
                except:
                    continue
                    
        except Exception as e:
            print(f"[!] Read entities error: {e}")
            
        return entities
        
    def read_entity(self, ptr):
        """读取单个实体完整信息"""
        data = self.reader.read_bytes(ptr, 0x80)
        if not data or len(data) < 0x60:
            return None
            
        try:
            health = struct.unpack('<f', data[0x18:0x1C])[0]
            max_hp = struct.unpack('<f', data[0x1C:0x20])[0]
            team_id = struct.unpack('<i', data[0x24:0x28])[0]
            pos = struct.unpack('<fff', data[0x30:0x3C])
            name = self.reader.read_string(ptr + 0x40)
            
            entity = {
                'ptr': ptr,
                'health': health,
                'max_health': max_hp,
                'hp_percent': health / max_hp if max_hp > 0 else 0,
                'team_id': team_id,
                'position': {'x': pos[0], 'y': pos[1], 'z': pos[2]},
                'name': name or 'Unknown',
                'type': self._classify_entity(team_id, name, ptr),
                'timestamp': time.time()
            }
            return entity
        except:
            return None
            
    def _classify_entity(self, team_id, name, ptr):
        """分类实体类型"""
        name_lower = (name or '').lower()
        if 'hero' in name_lower or 'player' in name_lower:
            return 'hero'
        elif 'monster' in name_lower or 'boss' in name_lower or 'dragon' in name_lower or 'buff' in name_lower:
            return 'monster'
        elif 'minion' in name_lower or 'soldier' in name_lower:
            return 'minion'
        elif team_id == 0:
            return 'neutral'
        else:
            return 'unknown'

    def close(self):
        self.reader.close()


class ESPServer:
    def __init__(self):
        self.pid = None
        self.scanner = None
        self.running = False
        self.clients = []
        self.lock = threading.Lock()
        
    def find_game_pid(self):
        try:
            import subprocess
            result = subprocess.run(['pidof', TARGET_PKG], capture_output=True, text=True)
            if result.stdout.strip():
                self.pid = int(result.stdout.strip().split()[0])
                return self.pid
        except:
            pass
        return None
        
    def setup_socket(self):
        os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
        try:
            os.unlink(SOCKET_PATH)
        except:
            pass
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(SOCKET_PATH)
        self.server.listen(5)
        os.chmod(SOCKET_PATH, 0o666)
        print(f"[+] ESP Socket listening on {SOCKET_PATH}")
        
    def accept_clients(self):
        while self.running:
            try:
                client, _ = self.server.accept()
                with self.lock:
                    self.clients.append(client)
                print(f"[+] Client connected, total: {len(self.clients)}")
            except:
                break
                
    def broadcast(self, data):
        msg = json.dumps(data).encode() + b'\n'
        dead = []
        with self.lock:
            for client in self.clients:
                try:
                    client.send(msg)
                except:
                    dead.append(client)
            for d in dead:
                self.clients.remove(d)
                try:
                    d.close()
                except:
                    pass
                    
    def scan_loop(self):
        while self.running:
            if not self.pid or not self.scanner:
                self.pid = self.find_game_pid()
                if self.pid:
                    self.scanner = EntityScanner(self.pid)
                    self.scanner.scan_unity_regions()
                    self.scanner.find_entity_list()
                    print(f"[+] Game attached: PID={self.pid}")
                else:
                    time.sleep(2)
                    continue
                    
            try:
                entities = self.scanner.read_entities()
                if entities:
                    # 分离队友/敌人/中立
                    allies = [e for e in entities if e['team_id'] == 1]  # 假设 1 是己方
                    enemies = [e for e in entities if e['team_id'] == 2]  # 假设 2 是敌方
                    neutrals = [e for e in entities if e['team_id'] not in (1, 2)]
                    
                    self.broadcast({
                        'type': 'entities',
                        'timestamp': time.time(),
                        'allies': allies,
                        'enemies': enemies,
                        'neutrals': neutrals,
                        'count': len(entities)
                    })
                    
            except Exception as e:
                print(f"[!] Scan error: {e}")
                self.scanner = None  # 重新初始化
                
            time.sleep(SCAN_INTERVAL)
            
    def run(self):
        self.running = True
        self.setup_socket()
        
        # 启动接受线程
        accept_thread = threading.Thread(target=self.accept_clients, daemon=True)
        accept_thread.start()
        
        # 主扫描循环
        self.scan_loop()
        
    def stop(self):
        self.running = False
        try:
            self.server.close()
        except:
            pass


if __name__ == '__main__':
    server = ESPServer()
    try:
        server.run()
    except KeyboardInterrupt:
        server.stop()
        print("\n[+] ESP Server stopped")