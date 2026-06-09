#!/usr/bin/env python3
import argparse
import fcntl
import json
import os
import pty
import random
import re
import select
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
import urllib.error
import urllib.request

SHELL_PORT = 48484
MARK = b"\xff\xfe\xfd"
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

SSH_OPTS = [
    "-F", "/dev/null",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ServerAliveInterval=30",
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "IdentityFile=/dev/null",
    "-o", "PubkeyAuthentication=no",
]


def rand(n=6):
    return "".join(random.choice(ALPHA) for _ in range(n))


def winsize(fd):
    try:
        r = struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 4))
        return r if r != (0, 0) else (24, 80)
    except Exception:
        return (24, 80)


def set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("hh", rows, cols))
    except Exception:
        pass


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ntfy_post(code, data):
    req = urllib.request.Request(
        f"https://ntfy.sh/mc-{code}",
        data=json.dumps(data).encode(),
        headers={"Title": "mc", "Priority": "5"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10).read()


def ntfy_wait(code, timeout=120):
    url = f"https://ntfy.sh/mc-{code}/json?poll=1&since=0"
    end = time.time() + timeout
    while time.time() < end:
        try:
            raw = urllib.request.urlopen(url, timeout=15).read().decode()
            for line in raw.strip().splitlines():
                msg = json.loads(line)
                if msg.get("event") != "message":
                    continue
                return json.loads(msg["message"])
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            pass
        time.sleep(1)
    raise SystemExit("timed out — is main.py still running at home?")


def parse_tunnel_output(text):
    for pat in [
        r"([a-z0-9.-]+\.lhr\.life)[:\s]+(\d+)",
        r"([a-z0-9.-]+\.localhost\.run)[:\s]+(\d+)",
        r"connect to[:\s]+([a-z0-9.-]+)[:\s]+(\d+)",
    ]:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1), int(m.group(2))
    return None, None


def open_tunnel():
    env = os.environ.copy()
    env.pop("SSH_AUTH_SOCK", None)

    proc = subprocess.Popen(
        ["ssh", *SSH_OPTS, "-R", f"0:localhost:{SHELL_PORT}", "nokey@localhost.run"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    buf = []
    end = time.time() + 30
    while time.time() < end and proc.poll() is None:
        line = proc.stdout.readline() if proc.stdout else ""
        if line:
            buf.append(line)
            host, port = parse_tunnel_output("".join(buf))
            if host:
                return host, port, proc
        elif not line and proc.poll() is not None:
            break

    proc.kill()
    return None, None, None


def relay_shell(sock):
    if sys.platform == "win32":
        p = subprocess.Popen(
            [os.environ.get("COMSPEC", "cmd.exe")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        while True:
            r, _, _ = select.select([sock, p.stdout], [], [])
            if p.stdout in r:
                d = p.stdout.read(4096)
                if not d:
                    break
                sock.sendall(d)
            if sock in r:
                d = sock.recv(4096)
                if not d:
                    break
                p.stdin.write(d)
                p.stdin.flush()
        p.kill()
        return

    pid, master = pty.fork()
    if pid == 0:
        os.environ["TERM"] = os.environ.get("TERM", "xterm-256color")
        sh = os.environ.get("SHELL") or ("/bin/zsh" if sys.platform == "darwin" else "/bin/bash")
        os.execvp(sh, [sh, "-l"])

    set_winsize(master, *winsize(0))
    while True:
        r, _, _ = select.select([sock, master], [], [])
        if master in r:
            try:
                d = os.read(master, 4096)
            except OSError:
                break
            if not d:
                break
            sock.sendall(d)
        if sock in r:
            try:
                d = sock.recv(4096)
            except OSError:
                break
            if not d:
                break
            if d.startswith(MARK) and len(d) >= len(MARK) + 4:
                rows, cols = struct.unpack("!HH", d[len(MARK) : len(MARK) + 4])
                set_winsize(master, rows, cols)
                rest = d[len(MARK) + 4 :]
                if rest:
                    os.write(master, rest)
            else:
                os.write(master, d)
    try:
        os.close(master)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def accept_loop(secret):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", SHELL_PORT))
    srv.listen(5)
    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(8)
            if conn.recv(32).decode().strip() != secret:
                conn.close()
                continue
            conn.settimeout(None)
            conn.sendall(b"ok\n")
            relay_shell(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def wait_forever():
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  bye\n")


def host_mode():
    code = rand()
    secret = rand(8)
    ip = local_ip()

    t = threading.Thread(target=accept_loop, args=(secret,), daemon=True)
    t.start()
    time.sleep(0.2)

    print("\n  opening tunnel…")
    th, tp, proc = open_tunnel()

    if th:
        ntfy_post(code, {"h": th, "p": tp, "k": secret})
        print(f"\n  ready")
        print(f"  code   {code}")
        print(f"  run    python3 main.py {code}")
        print(f"\n  keep this window open\n")
        try:
            proc.wait()
        except KeyboardInterrupt:
            print("\n  bye\n")
            proc.kill()
        return

    print(f"\n  tunnel failed — same wifi only")
    print(f"  code   {code}")
    print(f"  ip     {ip}")
    print(f"  run    python3 main.py {code} --ip {ip} --key {secret}")
    print(f"\n  keep this window open\n")
    wait_forever()


def client_mode(code, ip=None, key=None):
    if ip:
        if not key:
            key = input("  key: ").strip()
        sock = socket.create_connection((ip, SHELL_PORT), timeout=8)
    else:
        print(f"\n  looking up {code}…")
        info = ntfy_wait(code.upper())
        sock = socket.create_connection((info["h"], info["p"]), timeout=15)
        key = info["k"]

    sock.sendall(key.encode())
    if sock.recv(8) != b"ok\n":
        raise SystemExit("bad key")

    print(f"\n  connected  (ctrl+c to quit)\n")

    if sys.platform == "win32":
        while True:
            d = sock.recv(4096)
            if not d:
                break
            sys.stdout.buffer.write(d)
            sys.stdout.buffer.flush()
        return

    old = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    rows, cols = winsize(sys.stdin.fileno())
    sock.sendall(MARK + struct.pack("!HH", rows, cols))
    try:
        while True:
            r, _, _ = select.select([sock, sys.stdin], [], [], 0.2)
            if sys.stdin in r:
                chunk = os.read(sys.stdin.fileno(), 4096)
                if not chunk:
                    break
                sock.sendall(chunk)
            if sock in r:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                os.write(sys.stdout.fileno(), chunk)
            nr, nc = winsize(sys.stdin.fileno())
            if (nr, nc) != (rows, cols):
                rows, cols = nr, nc
                sock.sendall(MARK + struct.pack("!HH", rows, cols))
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        sock.close()
    print("\n  done\n")


def main():
    p = argparse.ArgumentParser(description="run at home, connect with code anywhere")
    p.add_argument("code", nargs="?", help="code from home screen")
    p.add_argument("--ip", help="same-wifi fallback")
    p.add_argument("--key")
    args = p.parse_args()

    if args.code:
        client_mode(args.code.upper(), args.ip, args.key)
    else:
        try:
            host_mode()
        except KeyboardInterrupt:
            print("\n  bye\n")
        except OSError as e:
            if e.errno == 48:
                print(f"\n  port {SHELL_PORT} busy — kill old session:")
                print(f"  lsof -ti :{SHELL_PORT} | xargs kill\n")
            raise


if __name__ == "__main__":
    main()
