#!/usr/bin/env python3
"""Run MMTOOL 4.50 CLI with a short timeout and always leave a clean desktop.

MMTOOL_4.50.0.23.exe is a **GUI-subsystem** PE (Subsystem == 2) with a text-mode
UI: given valid CLI args it AllocConsoles, prints a report, and blocks in
ReadConsoleInputA waiting for Esc.  Launched from a pipe it has no console, so
ReadConsoleInputA fails and it dies with 0xC000013A (STATUS_CONTROL_C_EXIT).
The console window it creates belongs to a **conhost.exe child**, not to MMTool's
own pid -- which is why closing windows by MMTool's pid finds nothing and a
window is left on screen.  Everything here is therefore short-timeout and
self-cleaning.

    python mmtool_run.py <rom> <args...> [--expect F[,F]] [--timeout S] [--pty]

    python mmtool_run.py probe.rom /s
    python mmtool_run.py probe.rom /s --pty                  # real console via ConPTY
    python mmtool_run.py probe.rom /ec <GUID> mod.bin --expect mod.bin
    python mmtool_run.py probe.rom /rc <GUID> mod.bin --expect probe.rom
    python mmtool_run.py --kill-orphans

Default timeout is 6 s: MMTool either acts quickly or it is waiting for a key.
Teardown always runs: WM_CLOSE to every window of MMTool, its conhost children
and any winpty-agent, then taskkill /F /T, then a final orphan sweep.
Exit code is MMTool's own; 124 on timeout.
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WM_CLOSE = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
TH32CS_SNAPPROCESS = 0x00000002
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
WAIT_OBJECT_0 = 0x00000000

EXE = 'MMTOOL_4.50.0.23.exe'
DEFAULT_TIMEOUT = 6.0

ANSI_CSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z@`]')
ANSI_MISC = re.compile(r'\x1b[()][0-9A-B]|\x1b[=>]|\x1b\][^\x07]*\x07')


class PE32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD),
                ('th32ProcessID', wt.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                ('th32ModuleID', wt.DWORD), ('cntThreads', wt.DWORD),
                ('th32ParentProcessID', wt.DWORD),
                ('pcPriClassBase', ctypes.c_long), ('dwFlags', wt.DWORD),
                ('szExeFile', ctypes.c_char * 260)]


EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)


def enum_procs():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    out = []
    try:
        e = PE32()
        e.dwSize = ctypes.sizeof(PE32)
        if kernel32.Process32First(snap, ctypes.byref(e)):
            while True:
                out.append((int(e.th32ProcessID), int(e.th32ParentProcessID),
                            e.szExeFile.decode('mbcs', 'replace')))
                if not kernel32.Process32Next(snap, ctypes.byref(e)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return out


def child_pids(ppid):
    return [(p, nm) for p, pp, nm in enum_procs() if pp == ppid]


def alive(pid):
    h = kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not h:
        return False
    try:
        return kernel32.WaitForSingleObject(h, 0) != WAIT_OBJECT_0
    finally:
        kernel32.CloseHandle(h)


def window_titles(pid):
    """All top-level windows owned by `pid` as (hwnd, title, visible)."""
    titles = []

    @EnumWindowsProc
    def cb(hwnd, lparam):
        p = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            n = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            titles.append((hwnd, buf.value, bool(user32.IsWindowVisible(hwnd))))
        return True

    user32.EnumWindows(cb, 0)
    return titles


def close_windows_matching(needle):
    """WM_CLOSE every visible top-level window whose title contains `needle`."""
    seen = []

    @EnumWindowsProc
    def cb(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            if needle.lower() in buf.value.lower():
                p = wt.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
                seen.append((hwnd, buf.value, p.value))
        return True

    user32.EnumWindows(cb, 0)
    for hwnd, title, pid in seen:
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
    return seen


def close_windows(pid):
    closed = [t for t in window_titles(pid) if t[2]]
    for hwnd, _title, _v in closed:
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
    return closed


def taskkill(pid, tree=True):
    return subprocess.run(['taskkill', '/F'] + (['/T'] if tree else []) + ['/PID', str(pid)],
                          capture_output=True, text=True)


def kill_orphans():
    """Kill leftover MMTool / winpty-agent processes and close their windows."""
    me = os.getpid()
    killed = []
    for pid, pp, nm in enum_procs():
        if pid == me:
            continue
        if nm.lower().startswith('winpty') or nm.upper().startswith('MMTOOL'):
            for hwnd, title, vis in window_titles(pid):
                if vis:
                    user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            close_windows_matching('MMTool')
            taskkill(pid)
            killed.append((pid, nm))
    return killed


def find_exe(start=None):
    d = os.path.abspath(start or os.getcwd())
    for _ in range(6):
        c = os.path.join(d, EXE)
        if os.path.exists(c):
            return c
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.environ.get('MMTOOL_EXE')


def artefacts(paths):
    return {p: ((os.path.getsize(p), os.path.getmtime(p)) if os.path.exists(p) else None)
            for p in paths}


def teardown(p, kids, exe):
    """Close every window MMTool (or its conhost/winpty children) owns."""
    for _ in range(6):
        for pid in [p.pid] + list(kids):
            close_windows(pid)
        close_windows_matching(os.path.basename(exe))
        close_windows_matching('MMTool')
        close_windows_matching('MMTOOL')
        time.sleep(0.25)
        if not alive(p.pid) and not any(alive(k) for k in kids):
            break
    if alive(p.pid):
        taskkill(p.pid)
    for k in list(kids):
        if alive(k):
            taskkill(k)
    kill_orphans()


def windows_left(pids):
    return sum(len([t for t in window_titles(pid) if t[2]]) for pid in pids)


def run_pty(cmd, expect, before, timeout, exe):
    """Give MMTool a real console (ConPTY) and capture its screen text."""
    from winpty import PtyProcess
    p = PtyProcess.spawn(cmd, cwd=os.getcwd(), dimensions=(80, 300))
    out, rc, reason = [], None, 'exited'
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = p.read(4096)
        except (EOFError, OSError):
            break
        if s:
            out.append(s)
        after = artefacts(expect)
        if expect and all(after[q] is not None and after[q] != before.get(q) for q in expect):
            reason = 'wrote %s' % ','.join(os.path.basename(q) for q in expect)
            break
        time.sleep(0.15)
    else:
        reason = 'timeout'
    for key in ('\x1b', '\r'):
        try:
            p.write(key)
            time.sleep(0.2)
        except (EOFError, OSError):
            break
    try:
        rc = p.wait()
    except Exception:
        rc = None
    p.terminate(force=True)
    kill_orphans()
    txt = ANSI_MISC.sub('', ANSI_CSI.sub('', ''.join(out)))
    txt = re.sub(r'\n{3,}', '\n\n', txt).strip()
    if txt:
        print(txt)
    return reason, rc, set()


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == '--kill-orphans':
        k = kill_orphans()
        print('killed: %s' % (k or 'nothing'))
        return 0

    expect, timeout, pty = [], DEFAULT_TIMEOUT, '--pty' in argv
    if pty:
        argv.remove('--pty')
    log = None
    for flag, n in (('--expect', 1), ('--timeout', 1), ('--log', 1)):
        if flag in argv:
            i = argv.index(flag)
            v = argv[i + 1]
            del argv[i:i + 2]
            if flag == '--expect':
                expect = [os.path.abspath(x) for x in v.split(',')]
            elif flag == '--timeout':
                timeout = float(v)
            else:
                log = os.path.abspath(v)

    exe = find_exe()
    if not exe:
        print('MMTool not found (%s)' % EXE)
        return 127
    if not os.path.exists(argv[0]):
        print('ROM not found: %s' % argv[0])
        return 2
    argv[0] = os.path.abspath(argv[0])

    before = artefacts(expect)
    cmd = [exe] + argv
    print('+ ' + ' '.join(cmd), flush=True)

    if pty:
        reason, rc, kids = run_pty(cmd, expect, before, timeout, exe)
        p = None
    else:
        # MMTool's text-mode UI writes its reports with WriteFile on the
        # standard handle: redirect stdout to a real file and the whole report
        # is captured.  DEVNULL (the old behaviour) throws it away.
        if log is None:
            log = os.path.splitext(os.path.abspath(argv[0]))[0] + '.mmtool.log'
        lh = open(log, 'wb')
        p = subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                             stdin=subprocess.DEVNULL, stdout=lh, stderr=subprocess.STDOUT)
        rc, reason, kids = None, 'exited', set()
        t0 = time.time()
        while time.time() - t0 < timeout:
            kids.update(pid for pid, _n in child_pids(p.pid))
            rc = p.poll()
            if rc is not None:
                break
            after = artefacts(expect)
            if expect and all(after[q] is not None and after[q] != before.get(q) for q in expect):
                reason = 'wrote %s' % ','.join(os.path.basename(q) for q in expect)
                time.sleep(0.5)
                break
            time.sleep(0.2)
        else:
            reason = 'timeout'
        if rc is None:
            try:
                rc = p.wait(timeout=3)
            except Exception:
                rc = 124
        lh.close()

    teardown(p, kids, exe) if p else None
    note = {0xc000013a: ' (MMTool finished: its Esc path exits STATUS_CONTROL_C_EXIT)'}
    print('[%s exit=%s%s]' % (reason, rc, note.get(rc & 0xffffffff, '') if rc else ''))
    for q in expect:
        print('  %-28s %s' % (os.path.basename(q),
                              '%s bytes' % f'{os.path.getsize(q):,}' if os.path.exists(q) else 'MISSING'))
    print('[children: %s]  [windows left: %d]' % (','.join(map(str, sorted(kids))) or 'none',
                                                  windows_left([p.pid] + list(kids)) if p else 0))
    if log and os.path.exists(log):
        txt = open(log, 'rb').read().decode('mbcs', 'replace')
        print('--- %s (%s bytes) ---' % (os.path.basename(log), f'{len(txt):,}'))
        print(txt.rstrip())
    return rc if rc is not None else 124


if __name__ == '__main__':
    sys.exit(main())
