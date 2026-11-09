#!/usr/bin/env python3
"""
OSSYS - Corrupted File & Malware Scanner  (desktop app)
=======================================================

Run:   python ossys.py

Needs corrupt_scanner.py in the SAME folder (it provides the corruption checks).
Only the Python standard library is required (tkinter ships with Python on
Windows/macOS; on Linux install it with e.g. `sudo apt install python3-tk`).

Scan targets : a single file, a folder, a specific drive, or the whole system.
Scan types   : corruption check, malware check (or both).

Malware detection is layered:
  1. EICAR test-file detection (harmless standard AV test string).
  2. Known-bad SHA-256 hash list  (malware_hashes.txt next to this script, or
     load one from the app).
  3. Heuristics: double extensions (invoice.pdf.exe), executables disguised as
     documents/images, obfuscated or abusive script commands, packed
     executables in temp folders.
  4. ClamAV engine, if installed (strongly recommended - real signature DB).

IMPORTANT: this is NOT a replacement for a full antivirus. Heuristic hits are
"suspicious", not proof of infection - review them before deleting anything.
The program only reads files; it never deletes, moves or modifies anything.
"""

import csv
import hashlib
import json
import math
import os
import platform
import queue
import re
import shutil
import string
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Set, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import corrupt_scanner as cs
except ImportError:
    sys.exit("ERROR: corrupt_scanner.py must be in the same folder as ossys.py")

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:  # pragma: no cover
    tk = ttk = filedialog = messagebox = None

# --------------------------------------------------------------------------- #
# Malware detection
# --------------------------------------------------------------------------- #

# The EICAR string is split so antivirus software doesn't flag this very file.
EICAR_SIG = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
             b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".dll", ".sys", ".msi"}
SCRIPT_EXT = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
              ".ps1", ".psm1", ".sh", ".php"}
# Extensions that should never contain a program.
DATA_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".txt", ".doc",
            ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".mp3", ".mp4", ".avi",
            ".mkv", ".wav", ".csv", ".rtf", ".zip", ".rar", ".7z"}

DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)"
    r"\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|hta|lnk|ps1)$")
TEMP_RE = re.compile(r"[\\/](temp|tmp)[\\/]|appdata[\\/]local[\\/]temp")

# (regex, weight, label)  - weight >= 3 is a strong indicator on its own.
SCRIPT_PATTERNS = [
    (rb"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{30,}", 3, "encoded PowerShell command"),
    (rb"certutil(\.exe)?\s+.*-urlcache", 3, "certutil used as downloader"),
    (rb"mshta\s+https?://", 3, "mshta remote execution"),
    (rb"regsvr32\s+/s\s+/n\s+/u\s+/i:https?", 3, "regsvr32 remote script"),
    (rb"base64\s+-d\s*\|\s*(ba|z)?sh", 3, "decodes and pipes payload to shell"),
    (rb"eval\(\s*base64_decode", 3, "PHP eval(base64_decode(...))"),
    (rb"vssadmin\s+delete\s+shadows", 3, "deletes shadow copies (ransomware behavior)"),
    (rb"-windowstyle\s+hidden|-w\s+hidden", 2, "hidden PowerShell window"),
    (rb"bitsadmin\s+/transfer", 2, "bitsadmin download"),
    (rb"/dev/tcp/", 2, "bash reverse-shell style socket"),
    (rb"bcdedit.*recoveryenabled\s+no", 2, "disables recovery (ransomware behavior)"),
    (rb"frombase64string", 1, "base64 decoding"),
    (rb"invoke-expression|\biex\b", 1, "dynamic code execution"),
    (rb"downloadstring|downloadfile|invoke-webrequest|net\.webclient", 1, "downloads from the internet"),
    (rb"wscript\.shell", 1, "WScript.Shell usage"),
]
SCRIPT_RES = [(re.compile(p, re.I | re.S), w, lbl) for p, w, lbl in SCRIPT_PATTERNS]
SUSPICIOUS_THRESHOLD = 3
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def load_hashes(path: str) -> Set[str]:
    """Load SHA-256 hashes (one per line, '#' comments allowed)."""
    out: Set[str] = set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.split("#", 1)[0].strip()
                if not s:
                    continue
                tok = re.split(r"[\s,;]+", s)[0]
                if HEX64.match(tok):
                    out.add(tok.lower())
    except OSError:
        pass
    return out


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def scan_malware(path: str, size: int, hashes: Set[str],
                 max_hash_bytes: int = 100 * 1024 * 1024) -> Optional[Tuple[str, str]]:
    """Return ("malware" | "suspicious", detail) or None if nothing found."""
    p = path.lower()
    name = os.path.basename(p)
    ext = os.path.splitext(name)[1]
    is_exec = ext in EXEC_EXT
    is_script = ext in SCRIPT_EXT
    score = 0
    reasons: List[str] = []

    if DOUBLE_EXT_RE.search(name):
        score += 5
        reasons.append("double extension (disguised program)")

    need_head = is_exec or is_script or ext in DATA_EXT or size <= 4096
    head = b""
    digest = None
    try:
        with open(path, "rb") as f:
            if hashes and size <= max_hash_bytes:
                h = hashlib.sha256()
                first = f.read(cs.CHUNK)
                head = first[:262144]
                h.update(first)
                while True:
                    block = f.read(cs.CHUNK)
                    if not block:
                        break
                    h.update(block)
                digest = h.hexdigest()
            elif need_head:
                head = f.read(262144 if (is_exec or is_script) else 4096)
    except OSError:
        return None

    if size <= 4096 and EICAR_SIG in head:
        return ("malware", "EICAR antivirus test file")
    if digest and digest in hashes:
        return ("malware", f"matches known-malware hash {digest[:16]}...")

    is_pe = head[:2] == b"MZ"
    is_elf = head[:4] == b"\x7fELF"
    if (is_pe or is_elf) and ext in DATA_EXT:
        score += 5
        kind = "Windows" if is_pe else "Linux"
        reasons.append(f"{kind} executable disguised as '{ext}' file")

    if is_pe and is_exec and len(head) >= 4096 and entropy(head) >= 7.2:
        score += 2
        reasons.append("high entropy (possibly packed/encrypted)")

    if (is_exec or is_script) and TEMP_RE.search(p):
        score += 1
        reasons.append("located in a temp folder")

    if is_script and head:
        for rx, weight, label in SCRIPT_RES:
            if rx.search(head):
                score += weight
                reasons.append(label)

    if score >= SUSPICIOUS_THRESHOLD:
        return ("suspicious", f"score {score}: " + "; ".join(reasons))
    return None


def find_clamscan() -> Optional[str]:
    exe = shutil.which("clamscan") or shutil.which("clamscan.exe")
    if exe:
        return exe
    for p in (r"C:\Program Files\ClamAV\clamscan.exe",
              r"C:\Program Files (x86)\ClamAV\clamscan.exe",
              "/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"):
        if os.path.exists(p):
            return p
    return None


# --------------------------------------------------------------------------- #
# Drives
# --------------------------------------------------------------------------- #

VIRTUAL_FS = {"proc", "sysfs", "devtmpfs", "tmpfs", "cgroup", "cgroup2", "devpts",
              "securityfs", "debugfs", "tracefs", "pstore", "bpf", "configfs",
              "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc",
              "efivarfs", "squashfs", "overlay", "ramfs"}


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def list_drives() -> List[Tuple[str, str]]:
    """Return [(display label, root path)] for every mounted drive/volume."""
    roots: List[str] = []
    system = platform.system()
    if system == "Windows":
        roots = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    elif system == "Darwin":
        roots = ["/"]
        vol = Path("/Volumes")
        if vol.exists():
            for p in sorted(vol.iterdir()):
                if os.path.realpath(str(p)) != "/":
                    roots.append(str(p))
    else:
        try:
            with open("/proc/mounts", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    dev, mnt, fs = parts[0], parts[1].replace("\\040", " "), parts[2]
                    if fs in VIRTUAL_FS or not dev.startswith("/dev/") \
                            or dev.startswith("/dev/loop"):
                        continue
                    if os.path.isdir(mnt) and mnt not in roots:
                        roots.append(mnt)
        except OSError:
            pass
        if not roots:
            roots = ["/"]
    out = []
    for r in roots:
        try:
            u = shutil.disk_usage(r)
            label = f"{r}    ({human(u.free)} free of {human(u.total)})"
        except OSError:
            label = r
        out.append((label, r))
    return out


# --------------------------------------------------------------------------- #
# Scan engine (runs in a background thread, talks to the GUI through a queue)
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    path: str
    category: str   # malware | suspicious | corrupted | warning | error
    detail: str
    size: int = 0


class ScanJob(threading.Thread):
    def __init__(self, q: "queue.Queue", roots: List[str], single_file: Optional[str],
                 recursive: bool, same_device: bool, do_corrupt: bool,
                 do_malware: bool, use_clam: bool, flag_empty: bool,
                 hashes: Set[str], workers: int = 6):
        super().__init__(daemon=True)
        self.q = q
        self.roots = roots
        self.single_file = single_file
        self.recursive = recursive
        self.same_device = same_device
        self.do_corrupt = do_corrupt
        self.do_malware = do_malware
        self.use_clam = use_clam and do_malware
        self.flag_empty = flag_empty
        self.hashes = hashes
        self.workers = max(1, workers)
        self.stop_event = threading.Event()
        self.count = 0

    # -- file discovery ---------------------------------------------------- #
    def _paths(self):
        if self.single_file:
            yield self.single_file
            return
        for root in self.roots:
            dev = None
            if self.same_device and os.name == "posix":
                try:
                    dev = os.stat(root).st_dev
                except OSError:
                    dev = None
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                        onerror=lambda e: None):
                if self.stop_event.is_set():
                    return
                if not self.recursive:
                    dirnames[:] = []
                else:
                    keep = []
                    for d in dirnames:
                        full = os.path.join(dirpath, d)
                        if cs.should_skip_dir(full, set()):
                            continue
                        if dev is not None:
                            try:
                                if os.stat(full).st_dev != dev:
                                    continue
                            except OSError:
                                continue
                        keep.append(d)
                    dirnames[:] = keep
                for fn in filenames:
                    yield os.path.join(dirpath, fn)

    # -- per-file work ------------------------------------------------------ #
    def _process(self, path: str):
        findings: List[Finding] = []
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                return path, findings
            size = os.path.getsize(path)
        except OSError:
            return path, findings

        if self.do_corrupt:
            r = cs.scan_file(path, 500, self.flag_empty)
            if r.status in ("corrupted", "warning", "error"):
                findings.append(Finding(path, r.status, r.detail, r.size))
        if self.do_malware and size > 0:
            m = scan_malware(path, size, self.hashes)
            if m:
                findings.append(Finding(path, m[0], m[1], size))
        return path, findings

    def _collect(self, done_futures):
        for fut in done_futures:
            if fut.cancelled():
                continue
            try:
                path, findings = fut.result()
            except Exception:
                continue
            self.count += 1
            for f in findings:
                self.q.put(("finding", f))
            if self.count % 25 == 0:
                self.q.put(("progress", self.count, path))

    # -- stages ------------------------------------------------------------- #
    def _builtin_stage(self):
        self.q.put(("stage", "Built-in scan"))
        pool = ThreadPoolExecutor(max_workers=self.workers)
        pending = set()
        try:
            for path in self._paths():
                if self.stop_event.is_set():
                    break
                pending.add(pool.submit(self._process, path))
                if len(pending) >= self.workers * 32:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    self._collect(done)
            if not self.stop_event.is_set() and pending:
                done, pending = wait(pending)
                self._collect(done)
        finally:
            for f in pending:
                f.cancel()
            pool.shutdown(wait=True)
        self.q.put(("progress", self.count, ""))

    def _clam_stage(self):
        exe = find_clamscan()
        if not exe:
            return
        self.q.put(("stage", "ClamAV engine"))
        cmd = [exe, "-i", "--no-summary"]
        if self.recursive and not self.single_file:
            cmd.append("-r")
        if os.name == "posix" and "/" in self.roots:
            cmd += [f"--exclude-dir=^{d}" for d in ("/proc", "/sys", "/dev", "/run")]
        cmd += [self.single_file] if self.single_file else list(self.roots)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", creationflags=flags)
        except OSError as e:
            self.q.put(("finding", Finding("ClamAV", "error", f"could not start: {e}")))
            return
        for line in proc.stdout:
            if self.stop_event.is_set():
                proc.kill()
                break
            line = line.rstrip()
            if line.endswith(" FOUND"):
                path, _, sig = line[:-6].rpartition(": ")
                try:
                    sz = os.path.getsize(path)
                except OSError:
                    sz = 0
                self.q.put(("finding", Finding(path, "malware", f"ClamAV: {sig}", sz)))
        proc.wait()

    def run(self):
        t0 = time.time()
        try:
            if self.do_corrupt or self.do_malware:
                self._builtin_stage()
            if self.use_clam and not self.stop_event.is_set():
                self._clam_stage()
        except Exception as e:  # pragma: no cover
            self.q.put(("fatal", f"{type(e).__name__}: {e}"))
        self.q.put(("done", {"files": self.count, "seconds": time.time() - t0,
                             "stopped": self.stop_event.is_set()}))


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #

BG = "#0b7a35"        # main green background
CARD = "#0e8f3f"      # slightly lighter panels
DARK = "#065a24"      # dark green accents
FG = "#ffffff"
SOFT = "#c8f7d6"
FONT = "Segoe UI" if platform.system() == "Windows" else "Helvetica"

LABELS = {"malware": "MALWARE", "suspicious": "SUSPICIOUS", "corrupted": "CORRUPTED",
          "warning": "WARNING", "error": "ERROR"}
TAG_COLORS = {"malware": "#ff9e9e", "suspicious": "#fff3a8", "corrupted": "#ffd3a1",
              "warning": "#d6ecff", "error": "#e6e6e6"}


class App(tk.Tk if tk else object):
    def __init__(self):
        super().__init__()
        try:  # crisp text on high-DPI Windows screens
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        self.title("OSSYS - Corrupted File & Malware Scanner")
        self.configure(bg=BG)
        self.geometry("1040x780")
        self.minsize(920, 680)

        self.q: "queue.Queue" = queue.Queue()
        self.job: Optional[ScanJob] = None
        self.running = False
        self.findings: List[Finding] = []
        self.counts = Counter()
        self.scanned = 0
        self.current = ""
        self.stage = ""
        self.drives: List[Tuple[str, str]] = []
        self.clam = find_clamscan()
        self.hashes: Set[str] = load_hashes(os.path.join(HERE, "malware_hashes.txt"))

        self.mode = tk.StringVar(value="folder")
        self.path_var = tk.StringVar()
        self.v_corrupt = tk.BooleanVar(value=True)
        self.v_malware = tk.BooleanVar(value=True)
        self.v_recursive = tk.BooleanVar(value=True)
        self.v_empty = tk.BooleanVar(value=False)
        self.v_clam = tk.BooleanVar(value=bool(self.clam))
        self.v_errors = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready. Choose what to scan, then press START SCAN.")
        self.counter_text = tk.StringVar()

        self._style()
        self._build()
        self._mode_changed()
        self._update_counters()

    # -- construction --------------------------------------------------------- #
    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Treeview", background="#ffffff", fieldbackground="#ffffff",
                    foreground="#111111", rowheight=24, font=(FONT, 10))
        s.configure("Treeview.Heading", background=DARK, foreground="#ffffff",
                    font=(FONT, 10, "bold"), relief="flat")
        s.map("Treeview.Heading", background=[("active", "#08702c")])
        s.configure("Green.Horizontal.TProgressbar", troughcolor=DARK, background="#ffffff",
                    bordercolor=DARK, lightcolor="#ffffff", darkcolor="#ffffff")

    def _button(self, parent, text, cmd, bg="#ffffff", fg=DARK, big=False):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                         activebackground="#e8ffe9", activeforeground=DARK,
                         disabledforeground="#7aa88a", relief="flat", bd=0,
                         padx=22 if big else 14, pady=10 if big else 7,
                         font=(FONT, 13 if big else 10, "bold"), cursor="hand2")

    def _check(self, parent, text, var, command=None):
        return tk.Checkbutton(parent, text=text, variable=var, command=command, bg=CARD,
                              fg=FG, selectcolor="#ffffff", activebackground=CARD,
                              activeforeground=FG, font=(FONT, 10), anchor="w",
                              disabledforeground="#9fd1ae")

    def _build(self):
        # Big title ---------------------------------------------------------
        tk.Label(self, text="OSSYS", bg=BG, fg=FG, font=(FONT, 64, "bold")).pack(pady=(14, 0))
        tk.Label(self, text="Corrupted File & Malware Scanner", bg=BG, fg=SOFT,
                 font=(FONT, 14)).pack(pady=(0, 10))

        # Target card -------------------------------------------------------
        card = tk.Frame(self, bg=CARD, padx=16, pady=12)
        card.pack(fill="x", padx=18)
        tk.Label(card, text="WHAT TO SCAN", bg=CARD, fg=SOFT,
                 font=(FONT, 9, "bold")).pack(anchor="w")
        row = tk.Frame(card, bg=CARD)
        row.pack(fill="x", pady=(4, 6))
        for text, val in (("Single file", "file"), ("Folder", "folder"),
                          ("Specific drive", "drive"), ("Whole system", "system")):
            tk.Radiobutton(row, text=text, value=val, variable=self.mode,
                           command=self._mode_changed, bg=CARD, fg=FG,
                           selectcolor="#ffffff", activebackground=CARD,
                           activeforeground=FG, font=(FONT, 11, "bold")
                           ).pack(side="left", padx=(0, 22))

        self.target_box = tk.Frame(card, bg=CARD)
        self.target_box.pack(fill="x")
        # path row (file / folder)
        self.path_row = tk.Frame(self.target_box, bg=CARD)
        self.path_entry = tk.Entry(self.path_row, textvariable=self.path_var,
                                   font=(FONT, 11), relief="flat")
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self._button(self.path_row, "Browse...", self._browse).pack(side="left", padx=(8, 0))
        # drive row
        self.drive_row = tk.Frame(self.target_box, bg=CARD)
        self.drive_combo = ttk.Combobox(self.drive_row, state="readonly", font=(FONT, 11))
        self.drive_combo.pack(side="left", fill="x", expand=True, ipady=4)
        self._button(self.drive_row, "Refresh", self._load_drives).pack(side="left", padx=(8, 0))
        # system note
        self.system_row = tk.Frame(self.target_box, bg=CARD)
        tk.Label(self.system_row, bg=CARD, fg=SOFT, font=(FONT, 10), justify="left",
                 text="Every drive and partition will be scanned. This can take a long time; "
                      "run as Administrator/root to reach protected files.").pack(anchor="w")

        # Options card -------------------------------------------------------
        opt = tk.Frame(self, bg=CARD, padx=16, pady=10)
        opt.pack(fill="x", padx=18, pady=(10, 0))
        tk.Label(opt, text="SCAN OPTIONS", bg=CARD, fg=SOFT,
                 font=(FONT, 9, "bold")).grid(row=0, column=0, sticky="w", columnspan=3)
        self._check(opt, "Check for corrupted files", self.v_corrupt).grid(row=1, column=0, sticky="w", padx=(0, 24))
        self._check(opt, "Scan for viruses / malware", self.v_malware).grid(row=1, column=1, sticky="w", padx=(0, 24))
        self.cb_recursive = self._check(opt, "Include subfolders", self.v_recursive)
        self.cb_recursive.grid(row=1, column=2, sticky="w")
        clam_text = ("Use ClamAV engine (detected)" if self.clam
                     else "Use ClamAV engine (not installed)")
        self.cb_clam = self._check(opt, clam_text, self.v_clam)
        self.cb_clam.grid(row=2, column=0, sticky="w", padx=(0, 24))
        if not self.clam:
            self.cb_clam.configure(state="disabled")
        self._check(opt, "Report empty (0-byte) files", self.v_empty).grid(row=2, column=1, sticky="w", padx=(0, 24))
        self._check(opt, "Show unreadable-file errors", self.v_errors,
                    command=self._refresh_tree).grid(row=2, column=2, sticky="w")

        # Buttons -------------------------------------------------------------
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=18, pady=12)
        self.btn_start = self._button(bar, "START SCAN", self._start, big=True)
        self.btn_start.pack(side="left")
        self.btn_stop = self._button(bar, "STOP", self._stop, bg="#b3261e", fg="#ffffff", big=True)
        self.btn_stop.pack(side="left", padx=10)
        self.btn_stop.configure(state="disabled")
        self._button(bar, "Export report", self._export, bg=DARK, fg="#ffffff").pack(side="right")
        self._button(bar, "Clear", self._clear, bg=DARK, fg="#ffffff").pack(side="right", padx=8)
        self._button(bar, "Load hash list", self._load_hash_file, bg=DARK, fg="#ffffff").pack(side="right")

        # Progress ------------------------------------------------------------
        tk.Label(self, textvariable=self.status, bg=BG, fg=FG, font=(FONT, 10),
                 anchor="w").pack(fill="x", padx=20)
        self.progress = ttk.Progressbar(self, mode="indeterminate",
                                        style="Green.Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=18, pady=(4, 6))
        tk.Label(self, textvariable=self.counter_text, bg=BG, fg=SOFT,
                 font=(FONT, 10, "bold"), anchor="w").pack(fill="x", padx=20)

        # Results ---------------------------------------------------------------
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=18, pady=(6, 4))
        cols = ("type", "file", "details")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        for c, w, t in (("type", 110, "Result"), ("file", 430, "File"), ("details", 400, "Details")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        for cat, color in TAG_COLORS.items():
            self.tree.tag_configure(cat, background=color)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._open_location)

        tk.Label(self, bg=BG, fg=SOFT, font=(FONT, 9), anchor="w",
                 text="Double-click a result to show it in your file manager.  Heuristic hits are "
                      "'suspicious', not proof of infection - review before deleting.  This tool only "
                      "reads files; it never deletes or changes anything."
                 ).pack(fill="x", padx=20, pady=(0, 8))
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- target handling ---------------------------------------------------------- #
    def _mode_changed(self):
        for w in (self.path_row, self.drive_row, self.system_row):
            w.pack_forget()
        m = self.mode.get()
        if m in ("file", "folder"):
            self.path_row.pack(fill="x")
        elif m == "drive":
            self.drive_row.pack(fill="x")
            if not self.drives:
                self._load_drives()
        else:
            self.system_row.pack(fill="x")
        self.cb_recursive.configure(state="normal" if m in ("folder",) else "disabled")

    def _load_drives(self):
        self.drives = list_drives()
        self.drive_combo["values"] = [d[0] for d in self.drives]
        if self.drives:
            self.drive_combo.current(0)

    def _browse(self):
        if self.mode.get() == "file":
            p = filedialog.askopenfilename(title="Choose a file to scan")
        else:
            p = filedialog.askdirectory(title="Choose a folder to scan")
        if p:
            self.path_var.set(os.path.normpath(p))

    def _load_hash_file(self):
        p = filedialog.askopenfilename(title="Choose a SHA-256 hash list (text file)")
        if p:
            new = load_hashes(p)
            self.hashes |= new
            messagebox.showinfo("OSSYS", f"Loaded {len(new):,} hashes.\n"
                                         f"Total known-malware hashes: {len(self.hashes):,}")

    # -- running a scan ------------------------------------------------------------ #
    def _start(self):
        if self.running:
            return
        if not (self.v_corrupt.get() or self.v_malware.get()):
            messagebox.showwarning("OSSYS", "Tick at least one scan type "
                                            "(corrupted files and/or malware).")
            return
        mode = self.mode.get()
        roots: List[str] = []
        single = None
        same_dev = False
        if mode == "file":
            p = os.path.expanduser(self.path_var.get().strip().strip('"'))
            if not os.path.isfile(p):
                messagebox.showerror("OSSYS", "That file does not exist.")
                return
            single = p
        elif mode == "folder":
            p = os.path.expanduser(self.path_var.get().strip().strip('"'))
            if not os.path.isdir(p):
                messagebox.showerror("OSSYS", "That folder does not exist.")
                return
            roots = [p]
        elif mode == "drive":
            i = self.drive_combo.current()
            if i < 0 or i >= len(self.drives):
                messagebox.showerror("OSSYS", "Choose a drive first.")
                return
            roots = [self.drives[i][1]]
            same_dev = True
        else:
            if not messagebox.askyesno("OSSYS", "Scan the WHOLE system?\n\nThis can take hours "
                                                "and works best when run as Administrator/root."):
                return
            roots = cs.system_roots()

        recursive = True if mode in ("drive", "system") else self.v_recursive.get()
        self._clear()
        self.job = ScanJob(self.q, roots, single, recursive, same_dev, self.v_corrupt.get(),
                           self.v_malware.get(), self.v_clam.get() and bool(self.clam),
                           self.v_empty.get(), self.hashes, workers=min(8, os.cpu_count() or 4))
        self.running = True
        self._set_running(True)
        self.job.start()
        self.after(100, self._poll)

    def _stop(self):
        if self.job and self.running:
            self.job.stop_event.set()
            self.status.set("Stopping...")

    def _set_running(self, on: bool):
        self.btn_start.configure(state="disabled" if on else "normal")
        self.btn_stop.configure(state="normal" if on else "disabled")
        if on:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _poll(self):
        try:
            for _ in range(500):
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "finding":
                    self._add_finding(msg[1])
                elif kind == "progress":
                    self.scanned, self.current = msg[1], msg[2]
                elif kind == "stage":
                    self.stage = msg[1]
                elif kind == "fatal":
                    messagebox.showerror("OSSYS", f"Scan failed:\n{msg[1]}")
                elif kind == "done":
                    self._finish(msg[1])
        except queue.Empty:
            pass
        self._update_counters()
        if self.running:
            shown = self.current if len(self.current) < 70 else "..." + self.current[-67:]
            self.status.set(f"[{self.stage}] {self.scanned:,} files checked   {shown}")
        if self.running or not self.q.empty():
            self.after(100, self._poll)

    def _finish(self, info: dict):
        self.running = False
        self._set_running(False)
        self.scanned = info["files"] or self.scanned
        bad = self.counts["malware"] + self.counts["suspicious"] + self.counts["corrupted"]
        verb = "Stopped" if info["stopped"] else "Finished"
        self.status.set(f"{verb}: {info['files']:,} files in {info['seconds']:.1f}s - "
                        f"{bad} problem(s) found.")
        self._update_counters()
        if not info["stopped"]:
            messagebox.showinfo("OSSYS", f"Scan finished.\n\nFiles checked: {info['files']:,}\n"
                                         f"Malware: {self.counts['malware']}\n"
                                         f"Suspicious: {self.counts['suspicious']}\n"
                                         f"Corrupted: {self.counts['corrupted']}")

    # -- results ---------------------------------------------------------------------- #
    def _visible(self, f: Finding) -> bool:
        return f.category != "error" or self.v_errors.get()

    def _insert(self, f: Finding):
        self.tree.insert("", "end", values=(LABELS[f.category], f.path, f.detail), tags=(f.category,))

    def _add_finding(self, f: Finding):
        self.findings.append(f)
        self.counts[f.category] += 1
        if self._visible(f):
            self._insert(f)

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for f in self.findings:
            if self._visible(f):
                self._insert(f)

    def _update_counters(self):
        c = self.counts
        self.counter_text.set(f"Files checked: {self.scanned:,}    Malware: {c['malware']}    "
                              f"Suspicious: {c['suspicious']}    Corrupted: {c['corrupted']}    "
                              f"Warnings: {c['warning']}    Unreadable: {c['error']}")

    def _clear(self):
        if self.running:
            return
        self.findings.clear()
        self.counts.clear()
        self.scanned = 0
        self.current = ""
        self.tree.delete(*self.tree.get_children())
        self._update_counters()

    def _export(self):
        if not self.findings:
            messagebox.showinfo("OSSYS", "Nothing to export yet.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv",
                                         filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not p:
            return
        try:
            if p.lower().endswith(".json"):
                with open(p, "w", encoding="utf-8") as fh:
                    json.dump([asdict(f) for f in self.findings], fh, indent=2)
            else:
                with open(p, "w", newline="", encoding="utf-8") as fh:
                    w = csv.writer(fh)
                    w.writerow(["category", "path", "detail", "size_bytes"])
                    for f in self.findings:
                        w.writerow([f.category, f.path, f.detail, f.size])
            messagebox.showinfo("OSSYS", f"Report saved:\n{p}")
        except OSError as e:
            messagebox.showerror("OSSYS", f"Could not save report:\n{e}")

    def _open_location(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        path = self.tree.item(sel[0], "values")[1]
        try:
            if platform.system() == "Windows":
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
        except Exception:
            pass

    def _on_close(self):
        if self.job and self.running:
            self.job.stop_event.set()
        self.destroy()


def main():
    if tk is None:
        sys.exit("tkinter is not installed. On Linux run:  sudo apt install python3-tk")
    App().mainloop()


if __name__ == "__main__":
    main()