import ssl
import serial
import time

# UART Configuration
UART_PORT = "/dev/ttyUSB1"
BAUD_RATE = 115200
ser = serial.Serial(UART_PORT, BAUD_RATE, timeout=0.1)

# Paths to certificate files
CLIENT_CERT = "client.crt"
CLIENT_KEY = "client.key"
CA_CERT = "ca.crt"

# Create an SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

# Memory BIOs for handling TLS over UART
in_bio = ssl.MemoryBIO()
out_bio = ssl.MemoryBIO()
ssl_obj = context.wrap_bio(in_bio, out_bio, server_hostname="espressif.local")


def send_pending_data():
    """Send pending TLS handshake messages over UART."""
    while out_bio.pending:
        data = out_bio.read()
        # print(f"Sending {len(data)} bytes over UART: {data.hex()}")
        ser.write(data)


def receive_uart_data():
    """Read from UART and write to TLS BIO."""
    data = ser.read(1024)
    if data:
        # print(f"Received UART data ({len(data)} bytes): {data.hex()}")
        in_bio.write(data)  # Write to Python SSL BIO
        process_tls_data()   # Ensure SSL sees the data


def process_tls_data():
    """Process any pending TLS data in the BIO."""
    try:
        while True:
            chunk = ssl_obj.read(4096)
            if not chunk:
                break
            print(f"TLS received data: {chunk}")
    except ssl.SSLWantReadError:
        pass  # Expected if there's no more data


def perform_tls_handshake():
    """Attempt TLS handshake, ensuring BIO processing."""
    while True:
        try:
            ssl_obj.do_handshake()
            print("TLS Handshake Completed!")
            return
        except ssl.SSLWantReadError:
            # print(f"TLS wants more data... (in_bio.pending: {in_bio.pending})")
            receive_uart_data()
            send_pending_data()
            time.sleep(0.05)
        except ssl.SSLWantWriteError:
            print("TLS wants to write data!")
            send_pending_data()
            time.sleep(0.05)
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")
            break
# Start handshake
perform_tls_handshake()

# TLS connection is established, now send/receive data
ssl_obj.write(b"Hello, TLS server over UART!")
send_pending_data()

while True:
    receive_uart_data()
    time.sleep(0.1)  # Prevent CPU spinning
