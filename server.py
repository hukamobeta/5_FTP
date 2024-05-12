import socket
import random
import threading
import json

def encrypt(key, message):
    return ''.join(chr((ord(char) + key) % 65536) for char in message)

def decrypt(key, cipher):
    return ''.join(chr((ord(char) - key) % 65536) for char in cipher)

def listen(conn):
    global private_key
    while True:
        msg = conn.recv(1024).decode()
        msg = decrypt(private_key, msg)
        print(msg)

def read_keys(addr):
    try:
        with open("server_key.json", "r") as keyfile:
            keys = json.load(keyfile)
            return keys.get(addr, None)
    except FileNotFoundError:
        return None

def get_keys(conn, addr):
    keys = read_keys(addr)
    if not keys:
        a, g, p = [random.randint(100,999) for _ in range(3)]
        my_a = pow(g, a, p)
        conn.send(f"{g}|{p}|{my_a}".encode())
        cli_b = int(conn.recv(1024).decode())
        private = pow(cli_b, a, p)
        keys = {'a': a, 'g': g, 'p': p, 'A': my_a, 'B': cli_b, 'private': private}
        with open("server_key.json", "w") as keyfile:
            json.dump({addr: keys}, keyfile)
    else:
        conn.send(f"{keys['g']}|{keys['p']}|{keys['A']}".encode())
        cli_b = int(conn.recv(1024).decode())
    return keys['private'], cli_b

def check_permission(cli_b):
    try:
        with open("allowed.json", "r") as keyfile:
            allowed = json.load(keyfile)
            return str(cli_b) in allowed
    except FileNotFoundError:
        return False

def create_socket(port=10101):
    sock = socket.socket()
    sock.bind(('', port))
    sock.listen(1)
    print(f"Socket bound at port {port}")
    conn, addr = sock.accept()
    return sock, conn, addr[0]

def messaging_port(conn):
    global private_key
    port = random.randint(1024, 65535)
    conn.send(encrypt(private_key, str(port)).encode())
    sock.close()
    return create_socket(port)

sock, conn, addr = create_socket()
private_key, client_b = get_keys(conn, addr)

if check_permission(client_b):
    sock, conn, addr = messaging_port(conn)
    threading.Thread(target=listen, args=(conn,), daemon=True).start()
    while True:
        cmd = input(">")
        if cmd.lower() == "stop":
            break
        conn.send(encrypt(private_key, cmd).encode())
else:
    print("Unknown client certificate")

sock.close()
