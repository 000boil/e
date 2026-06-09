#!/usr/bin/env python3
import argparse
import fcntl
import os
import pty
import random
import select
import socket
import ssl
import struct
import subprocess
import sys
import termios
import time
import tty

LAN_PORT = 48484
RELAY_PORT = 9000
CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MARK = b"\xff\xfe\xfd"


def pin(n=6):
    return "".join(random.choice(CODE_CHARS) for _ in range(n))


def addr(s):
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, RELAY_PORT


def ssl_sock(raw):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname="macctl")


def connect_relay(relay, role, code, key):
    host, port = addr(relay)
    raw = socket.create_connection((host, port), timeout=15)
    s = ssl_sock(raw)
    s.sendall(f"{role}\n{code}\n{key}\n".encode())
    line = b""
    while b"\n" not in line:
        line += s.recv(1)
    reply = line.decode().strip()
    if reply.startswith("ERR"):
        raise SystemExit(reply)
    if role == "HOST":
        while b"\n" not in line:
            chunk = s.recv(1)
            if not chunk:
                raise SystemExit("relay dropped host")
            line += chunk
    return s


def ips():
    out = set()
    try:
        for line in subprocess.check_output(["ifconfig"], text=True).splitlines():
            line = line.strip()
            if line.startswith("inet ") and "127.0.0.1" not in line:
                out.add(line.split()[1])
    except Exception:
        pass
    if not out:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            out.add(s.getsockname()[0])
        except Exception:
            out.add("127.0.0.1")
        finally:
            s.close()
    return sorted(out)


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


def send_resize(sock, rows, cols):
    sock.sendall(MARK + struct.pack("!HH", rows, cols))


def run_shell(sock):
    pid, master = pty.fork()
    if pid == 0:
        os.environ["TERM"] = os.environ.get("TERM", "xterm-256color")
        shell = os.environ.get("SHELL", "/bin/zsh")
        os.execvp(shell, [shell, "-l"])

    set_winsize(master, *winsize(0))

    while True:
        r, _, _ = select.select([sock, master], [], [])
        if master in r:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            sock.sendall(data)
        if sock in r:
            try:
                data = sock.recv(4096)
            except OSError:
                break
            if not data:
                break
            if data.startswith(MARK) and len(data) >= len(MARK) + 4:
                rows, cols = struct.unpack("!HH", data[len(MARK) : len(MARK) + 4])
                set_winsize(master, rows, cols)
                rest = data[len(MARK) + 4 :]
                if rest:
                    os.write(master, rest)
            else:
                os.write(master, data)

    try:
        os.close(master)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def client_session(sock, label):
    print(f"\n  macctl  → {label}")
    print("  ctrl+] q to quit\n")

    old = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    rows, cols = winsize(sys.stdin.fileno())
    send_resize(sock, rows, cols)

    try:
        while True:
            r, _, _ = select.select([sock, sys.stdin], [], [], 0.2)
            if sys.stdin in r:
                chunk = os.read(sys.stdin.fileno(), 4096)
                if not chunk or chunk == b"\x1d":
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
                send_resize(sock, rows, cols)
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        sock.close()
    print("\n  disconnected\n")


def tunnel(relay, code, key):
    print(f"\n  macctl  home tunnel")
    print(f"  relay   {relay}")
    print(f"  code    {code}")
    print(f"  ctrl+c to stop\n")

    while True:
        try:
            sock = connect_relay(relay, "HOST", code, key)
            print("  linked — waiting for you to connect from school")
            run_shell(sock)
            print("  session ended, reconnecting…")
        except KeyboardInterrupt:
            print("\n  bye\n")
            return
        except Exception as e:
            print(f"  {e}, retry in 3s")
        time.sleep(3)


def go_relay(relay, code, key):
    sock = connect_relay(relay, "JOIN", code, key)
    client_session(sock, relay)


def host_lan(port, code):
    code = code or pin()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    print(f"\n  macctl  lan host")
    print(f"  code    {code}")
    print(f"  port    {port}")
    for ip in ips():
        print(f"  ip      {ip}")
    print(f"\n  python3 macctl.py lan-go {ip} {code}\n")

    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(10)
            if conn.recv(64).decode().strip() != code:
                conn.sendall(b"no\n")
                conn.close()
                continue
            conn.sendall(b"ok\n")
            conn.settimeout(None)
            run_shell(conn)
        except Exception:
            pass
        finally:
            conn.close()


def go_lan(ip, port, code):
    sock = socket.create_connection((ip, port), timeout=8)
    sock.sendall(code.encode())
    if sock.recv(16) != b"ok\n":
        raise SystemExit("bad code")
    client_session(sock, ip)


def main():
    p = argparse.ArgumentParser(prog="macctl")
    sub = p.add_subparsers(dest="cmd")

    t = sub.add_parser("tunnel", help="run on home mac (works from anywhere)")
    t.add_argument("relay", help="your relay ip:port")
    t.add_argument("--code", default=pin())
    t.add_argument("--key", default=os.environ.get("MACCTL_KEY", "changeme"))

    g = sub.add_parser("go", help="connect from school / anywhere")
    g.add_argument("relay")
    g.add_argument("code")
    g.add_argument("--key", default=os.environ.get("MACCTL_KEY", "changeme"))

    h = sub.add_parser("host", help="same wifi only")
    h.add_argument("--port", type=int, default=LAN_PORT)
    h.add_argument("--code")

    l = sub.add_parser("lan-go", help="same wifi only")
    l.add_argument("ip")
    l.add_argument("code")
    l.add_argument("--port", type=int, default=LAN_PORT)

    args = p.parse_args()

    if args.cmd == "tunnel":
        tunnel(args.relay, args.code.upper(), args.key)
    elif args.cmd == "go":
        go_relay(args.relay, args.code.upper(), args.key)
    elif args.cmd == "host":
        try:
            host_lan(args.port, args.code.upper() if args.code else None)
        except KeyboardInterrupt:
            print("\n  bye\n")
    elif args.cmd == "lan-go":
        go_lan(args.ip, args.port, args.code.upper())
    else:
        print("""
  macctl — your macs, from anywhere

  1) put relay.py on a vps (once):
       python3 relay.py --key YOURSECRET

  2) home mac (leave running):
       python3 macctl.py tunnel YOUR_VPS:9000 --code HOME42 --key YOURSECRET

  3) school:
       python3 macctl.py go YOUR_VPS:9000 HOME42 --key YOURSECRET
""")


if __name__ == "__main__":
    main()
