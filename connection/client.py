import ssl
import socket

# Paths to certificate files
CLIENT_CERT = "client.crt"
CLIENT_KEY = "client.key"
CA_CERT = "ca.crt"

# Create an SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

# Connect to the TLS server
server_address = ('localhost', 3333)
with socket.create_connection(server_address) as sock:
    with context.wrap_socket(sock, server_hostname='espressif.local') as ssl_sock:
        print("Connected to server with TLS")
        ssl_sock.sendall(b"Hello, TLS server!")
        response = ssl_sock.recv(1024)
        print("Received:", response.decode())
