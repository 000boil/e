#!/usr/bin/env python3
import argparse
import os
import socket
import ssl
import subprocess
import threading

DEFAULT_PORT = 9000
hosts = {}
lock = threading.Lock()


def cert(dirpath):
    os.makedirs(dirpath, exist_ok=True)
    crt, key = os.path.join(dirpath, "relay.crt"), os.path.join(dirpath, "relay.key")
    if not os.path.exists(crt):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key, "-out", crt, "-days", "3650", "-nodes",
                "-subj", "/CN=macctl",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return crt, key


def readline(sock):
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf.decode().strip()


def bridge(a, b):
    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                src.shutdown(socket.SHUT_RD)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def handle(raw, key):
    try:
        role = readline(raw)
        pin = readline(raw)
        got = readline(raw)
        if got != key:
            raw.sendall(b"ERR bad key\n")
            return
        if role == "HOST":
            raw.sendall(b"OK wait\n")
            with lock:
                old = hosts.pop(pin, None)
                if old:
                    try:
                        old.close()
                    except OSError:
                        pass
                hosts[pin] = raw
            while True:
                data = raw.recv(1)
                if not data:
                    break
        elif role == "JOIN":
            with lock:
                host = hosts.pop(pin, None)
            if not host:
                raw.sendall(b"ERR no host\n")
                return
            raw.sendall(b"OK linked\n")
            host.sendall(b"OK linked\n")
            bridge(host, raw)
        else:
            raw.sendall(b"ERR role\n")
    except Exception:
        pass
    finally:
        with lock:
            for p, s in list(hosts.items()):
                if s is raw:
                    del hosts[p]
        try:
            raw.close()
        except OSError:
            pass


def run(port, key, tls):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)

    ctx = None
    if tls:
        crt, k = cert(os.path.dirname(os.path.abspath(__file__)))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, k)

    print(f"\n  relay up  0.0.0.0:{port}")
    print(f"  key       {key}")
    print(f"  tls       {tls}\n")

    while True:
        conn, addr = srv.accept()
        if ctx:
            conn = ctx.wrap_socket(conn, server_side=True)
        threading.Thread(target=handle, args=(conn, key), daemon=True).start()


def main():
    p = argparse.ArgumentParser(prog="relay", description="macctl rendezvous server")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--key", default=os.environ.get("MACCTL_KEY", "changeme"))
    p.add_argument("--no-tls", action="store_true")
    args = p.parse_args()
    if args.key == "changeme":
        print("  warning: set --key or MACCTL_KEY\n")
    run(args.port, args.key, not args.no_tls)


if __name__ == "__main__":
    main()
