#!/usr/bin/env python3
"""
AegisForge MiniProto Mock Server
A custom stateful TCP server with deterministic edge-case bugs designed
strictly for protocol fuzzing demonstrations inside the local sandbox.

Commands:
  HELO <client_name>     - Handshake
  AUTH <user>:<pass>     - Authenticate
  SET <key>=<val>        - Set key-value
  GET <key>              - Retrieve key-value
  STORE_PAYLOAD <data>   - Oversize buffer vulnerability demo
  SET_CHUNK_SIZE <n>     - Integer boundary bug demo
  LOG <msg>              - Format string inspection demo
  PING                   - Keepalive
  QUIT                   - Close session
"""

import socket
import sys
import threading

HOST = "0.0.0.0"
PORT = 5000

def handle_client(conn, addr):
    client_name = "Anonymous"
    authenticated = False
    storage = {}

    try:
        conn.sendall(b"220 MiniProto Stateful TCP Server v1.0 Ready\r\n")
        buffer = b""

        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data

            while b"\r\n" in buffer:
                line, buffer = buffer.split(b"\r\n", 1)
                line_str = line.decode("latin-1", errors="ignore").strip()

                if not line_str:
                    continue

                parts = line_str.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                # Bug Condition 1: Oversize buffer crash (> 1024 chars in STORE_PAYLOAD or AUTH)
                if len(line) >= 1024:
                    conn.sendall(b"500 FATAL: Stack smashing detected in local parser buffer!\r\n")
                    conn.close()
                    return

                # Bug Condition 2: Format string simulation in LOG command
                if cmd == "LOG" and "%n" in arg:
                    conn.sendall(b"500 SIGSEGV: Memory write violation via format string primitive\r\n")
                    conn.close()
                    return

                # Bug Condition 3: Signed integer overflow in SET_CHUNK_SIZE
                if cmd == "SET_CHUNK_SIZE":
                    try:
                        size_val = int(arg)
                        if size_val == 2147483647:
                            conn.sendall(b"500 INTEGER_OVERFLOW: Signed integer boundary exception\r\n")
                            conn.close()
                            return
                        conn.sendall(f"250 Chunk size set to {size_val}\r\n".encode())
                    except ValueError:
                        conn.sendall(b"400 Invalid integer parameter\r\n")
                    continue

                if cmd == "HELO":
                    client_name = arg or "Client"
                    conn.sendall(f"250 Hello {client_name}, welcome to AegisForge MiniProto\r\n".encode())
                elif cmd == "AUTH":
                    authenticated = True
                    conn.sendall(b"235 Authentication successful\r\n")
                elif cmd == "PING":
                    conn.sendall(b"PONG\r\n")
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye\r\n")
                    conn.close()
                    return
                else:
                    conn.sendall(b"200 OK\r\n")

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
        server.listen(10)
        print(f"[*] MiniProto Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down MiniProto Server.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
