import socket
import random
import threading
import json

def encrypt(key, message):
    return ''.join(chr((ord(char) + key) % 65536) for char in message)

def decrypt(key, cipher):
    return ''.join(chr((ord(char) - key) % 65536) for char in cipher)

def listen_to_socket(socket):
    while True:
        message = socket.recv(1024).decode()
        print(decrypt(private_key, message))

def read_keys():
    try:
        with open("client_key.json", "r") as keyfile:
            data = json.load(keyfile)
            return [data['b'], data['g'], data['p'], data['my_b'], data['serv_a'], data['private']]
    except FileNotFoundError:
        return None

def get_keys(sock):
    server_keys = map(int, sock.recv(1024).decode().split('|'))
    g, p, A = server_keys
    keys = read_keys()
    if not keys:
        b = random.randint(100, 999)
        my_b = pow(g, b, p)
        private = pow(A, b, p)
        keys = [b, g, p, my_b, A, private]
        with open("client_key.json", "w") as keyfile:
            json.dump({'b': b, 'g': g, 'p': p, 'my_b': my_b, 'serv_a': A, 'private': private}, keyfile)
    sock.send(str(keys[3]).encode())
    return keys

def main():
    sock = socket.socket()
    sock.connect(('localhost', 10101))
    print("Socket connected at port 10101")

    all_keys = get_keys(sock)
    global private_key
    private_key = all_keys[5]
    
    port = int(decrypt(private_key, sock.recv(1024).decode()))
    sock.close()

    sock = socket.socket()
    sock.connect(('localhost', port))
    print(f"Socket binded at port {port}")
    
    threading.Thread(target=listen_to_socket, args=(sock,), daemon=True).start()

    while True:
        cmd = input("Enter command: ")
        if cmd.lower() == "stop":
            break
        sock.send(encrypt(private_key, cmd).encode())

    sock.close()

main()
