import socket as libsock

addr = "127.0.0.1"

def client(port):
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    socket.connect((addr, port))  # SOCK_DGRAM es UDP
    socket.send("hola ql".encode()) # El saludo
    data, alo = socket.recvfrom(1024)
    print(alo)


def main():
    port = input("Ingrese su puerto: ")
    client(int(port))

main()