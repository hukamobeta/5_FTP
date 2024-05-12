import socket
import os
import shutil
import json
import re
import random

END_FLAG = b"$$STREAM_FILE_END_FLAG$$"
FAIL_FLAG = b'$FAILED$'
PORT = 6666
global_root = os.getcwd()
usersfile = os.path.join(global_root, "users.json")
log_file = os.path.join(global_root, "log.txt")

def encrypt(key, message):
    return ''.join(chr((ord(char) + key) % 65536) for char in message)

def decrypt(key, cipher):
    return ''.join(chr((ord(char) - key) % 65536) for char in cipher)

def get_keys(conn):
    a, g, p = [random.randint(100, 999) for _ in range(3)]
    my_a = pow(g, a, p)
    conn.send(f"{g}|{p}|{my_a}".encode())
    cli_b = int(conn.recv(1024).decode())
    private = pow(cli_b, a, p)
    return private

def custom_send(conn, data, key):
    encrypted_data = encrypt(key, data.decode())
    conn.send(encrypted_data.encode())

def custom_recv(conn, vol, key):
    data = conn.recv(vol).decode()
    decrypted_data = decrypt(key, data)
    return decrypted_data.encode()

def get_size(start_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)

    return total_size

socket.socket.custom_send = custom_send
socket.socket.custom_recv = custom_recv

def log_print(*args):
    print(*args)
    with open(log_file, "a") as logfile:
        logfile.write(" ".join(str(arg) for arg in args) + "\n")

def authorize(message):
    try:
        with open(usersfile, "r+") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}
    login_info = message.split("=")
    login, password, current_directory, size, message = login_info[0], login_info[1], login_info[2], int(login_info[3]), login_info[4]
    user_root = os.path.join(global_root, login)
    if login in users and users[login] == password:
        os.makedirs(user_root, exist_ok=True)
        return user_root, current_directory, message, size
    elif login not in users:
        users[login] = password
        with open(usersfile, "w") as f:
            json.dump(users, f)
        os.makedirs(user_root, exist_ok=True)
        return user_root, current_directory, message, size
    return None

def process_request(req):
    auth = authorize(req)
    if not auth:
        return "Incorrect password"
    user_root, current_directory, req, size = auth
    command, *path = req.split()
    path = path[0] if path else ""
    if command == 'pwd':
        return pwd(current_directory)
    elif command == 'ls':
        return ls(os.path.join(user_root, current_directory[1:]))
    elif command == 'cd':
        return cd(path, current_directory, user_root)
    elif command == 'mkdir':
        return mkdir(path)
    elif command == 'rmtree':
        return rmtree(path)
    elif command == 'touch':
        return touch(path)
    elif command == 'remove':
        return remove(path)
    elif command == 'cat':
        return cat(path)
    elif command == 'rename':
        return rename(*path[:2])
    elif command == "get_file":
        return get_file(path)
    elif command == "send_file":
        return send_file(path, user_root, size)
    return 'bad request'

def try_decorator(func):
    def wrapper(path, *args):
        try:
            return func(path, *args) or "Success"
        except FileNotFoundError:
            return 'Invalid path'
        except FileExistsError:
            return 'Already exists'
        except PermissionError:
            return 'Permission denied'
    return wrapper

def pwd(dirname):
    return os.path.join(dirname)

def ls(path):
    return '\n\r'.join(os.listdir(path))

def cd(path, current, root):
    try:
        os.chdir(path)
    except:
        return current
    return os.getcwd().replace(root,"")+"\\"

@try_decorator
def mkdir(path):
    os.makedirs(path)

@try_decorator
def rmtree(path):
    shutil.rmtree(path)

@try_decorator
def remove(path):
    os.remove(path)

@try_decorator
def touch(path):
    open(path, 'a').close()

@try_decorator
def cat(path):
    with open(path, "r") as file:
        return "\n".join(file.readlines())

@try_decorator
def rename(old, new):
    os.rename(old, new)

def get_file(path):
    global conn, END_FLAG, FAIL_FLAG
    try:
        with open(path, "rb") as bytefile:
            while read_bytes := bytefile.read(1024):
                conn.s_send(read_bytes)

    except FileNotFoundError:
        returned = b'Invalid path'+FAIL_FLAG
    except PermissionError:
        returned = b"Permission denied"+FAIL_FLAG
    else:
        returned =END_FLAG
    log_print("Has been sent")
    return returned

def send_file(path, root, size):
    global conn, END_FLAG, FAIL_FLAG
    available = pow(2,20)*10 - get_size(root) #10Mb for each user
    print(available, int(size))
    if available < int(size):
        return "Not enough disk space!"
    else:
        conn.s_send(b"$ENOUGHT$")
    flag_finder = conn.s_recv(1024)
    with open (path, "wb") as bytefile:
            while True:
                if END_FLAG in flag_finder:
                    bytefile.write(flag_finder.replace(END_FLAG, b""))
                    break
                else:
                    bytefile.write(flag_finder)
                    flag_finder = conn.s_recv(1024)
    log_print("Has been received")
    return "uploaded successfully"

# Setup server socket
with socket.socket() as sock:
    sock.bind(('', PORT))
    sock.listen()
    log_print("Listening on port", PORT)

    while True:
        conn, addr = sock.accept()
        private_key = get_keys(conn)
        request = conn.custom_recv(1024, private_key).decode()
        log_print("Request:", request)
        response = process_request(request)
        log_print("Response:", response)
        conn.custom_send(response.encode(), private_key)
