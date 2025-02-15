import sys
from pathlib import Path

def read_packet_header(data, offset):
    """Parse PGP packet header, return (tag, length, header_length)"""
    first_byte = data[offset]
    
    # Check if new format (bit 7 is set, bit 6 is 1)
    if (first_byte & 0x80) and (first_byte & 0x40):
        tag = first_byte & 0x3F
        offset += 1
        
        # Read new format length
        if offset >= len(data):
            return None, None, None
            
        length_byte = data[offset]
        if length_byte < 192:
            length = length_byte
            header_length = 2
        elif length_byte < 224:
            length = ((length_byte - 192) << 8) + data[offset + 1] + 192
            header_length = 3
        else:
            length = (data[offset + 1] << 24) + (data[offset + 2] << 16) + \
                    (data[offset + 3] << 8) + data[offset + 4]
            header_length = 6
            
    # Old format
    else:
        tag = (first_byte >> 2) & 0x0F
        length_type = first_byte & 0x03
        
        if length_type == 0:
            length = data[offset + 1]
            header_length = 2
        elif length_type == 1:
            length = (data[offset + 1] << 8) + data[offset + 2]
            header_length = 3
        elif length_type == 2:
            length = (data[offset + 1] << 24) + (data[offset + 2] << 16) + \
                    (data[offset + 3] << 8) + data[offset + 4]
            header_length = 5
        else:
            return None, None, None

    return tag, length, header_length

def hex_dump(data):
    return ''.join(f'{b:02X}' for b in data)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <encrypted.pgp>")
        sys.exit(1)

    # Read the encrypted file
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    offset = 0
    while offset < len(data):
        tag, length, header_length = read_packet_header(data, offset)
        if tag is None:
            break

        packet_start = offset + header_length
        packet_end = packet_start + length
        packet_data = data[packet_start:packet_end]

        # PKESK packet (tag 1)
        if tag == 1:
            print(f"Found PKESK packet, length: {length}")
            # Skip version (1 byte) and key ID (8 bytes)
            esk_data = packet_data[9:]
            with open("pkesk.bin", "wb") as f:
                f.write(esk_data)
        # SEIP packet (tag 18)
      # SEIP packet (tag 18)
        elif tag == 18:
            print(f"Found SEIP packet, length: {length}")
            print("Content structure:")
            print(f"  Version (1 byte):  {packet_data[0]:02x}")
            # Skip version byte for both display and IV usage
            print(f"  Prefix (16 bytes): {hex_dump(packet_data[1:17])}")
            print(f"  Data until hash:   {hex_dump(packet_data[17:-20])}")
            print(f"  Hash (20 bytes):   {hex_dump(packet_data[-20:])}")

            # Write the encrypted data excluding the version byte
            with open("encrypted.bin", "wb") as f:
                f.write(packet_data[1:])  # Skip version byte

            print("\nOpenSSL command:")
            # Use the correct IV (skip version byte)
            print(f"openssl enc -aes-256-cfb -d -K $KEY -iv {hex_dump(packet_data[2:18])} -in encrypted.bin")
        offset = packet_end

if __name__ == "__main__":
    main() 