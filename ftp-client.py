import socket
import re
import os
import random

HOST = 'localhost'
PORT = 6666
END_FLAG = b"$$STREAM_FILE_END_FLAG$$"
FAIL_FLAG = b'$FAILED$'
login = input("Введите логин: ")
password = input("Введите пароль: ")
current_directory = "\\"

def creator(message, size=0):
    return f"{login}=login{password}=password{current_directory}=cur_dir{size}=file_size{message}".encode()

def encrypt(key, message):
    return ''.join(chr((ord(char) + key) % 65536) for char in message)

def decrypt(key, cipher):
    return ''.join(chr((ord(char) - key) % 65536) for char in cipher)

def get_private_key(sock):
    server_keys = map(int, sock.recv(1024).decode().split("|"))  # g, p, A
    g, p, A = server_keys
    b = random.randint(100, 999)
    my_b = pow(g, b, p)
    sock.send(str(my_b).encode())
    private = pow(A, b, p)
    return private

def custom_send(sock, data, key):
    encrypted_data = encrypt(key, data.decode())
    sock.send(encrypted_data.encode())

def custom_recv(sock, volume, key):
    data = sock.recv(volume).decode()
    decrypted_data = decrypt(key, data)
    return decrypted_data.encode()

socket.socket.custom_send = custom_send
socket.socket.custom_recv = custom_recv

def receive_file(sock, request):
    filename = re.split("[ \\/]+", request)[-1]
    with open(filename, "wb") as bytefile:
        while True:
            data = sock.custom_recv(1024, private)
            if END_FLAG in data:
                data = data.replace(END_FLAG, b"")
                bytefile.write(data)
                break
            else:
                bytefile.write(data)

def send_file(sock, request):
    filename = re.split("[ \\/]+", request)[-1]
    if os.path.exists(filename):
        size = os.path.getsize(filename)
        sock.custom_send(creator(request, size), private)
        response = sock.custom_recv(1024, private).decode()
        if response != '$ENOUGHT$':
            print(response)
            return
        with open(filename, "rb") as bytefile:
            while read_bytes := bytefile.read(1024):
                sock.custom_send(read_bytes, private)
        sock.custom_send(END_FLAG, private)
    else:
        print("File not found.")
    print(sock.custom_recv(1024, private).decode())

def main():
    global private
    while True:
        request = input(current_directory + '>').strip()
        if request.lower() == "exit":
            print("Goodbye")
            break

        with socket.socket() as sock:
            sock.connect((HOST, PORT))
            private = get_private_key(sock)

            if request.startswith("send_file"):
                send_file(sock, request)
            elif request.startswith("get_file"):
                receive_file(sock, request)
            else:
                sock.custom_send(creator(request), private)
                response = sock.custom_recv(1024, private).decode()
                print(response)

main()
