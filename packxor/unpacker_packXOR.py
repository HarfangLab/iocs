import struct
import argparse
import pefile
import re

# Usage of LZNT1 decompress function code from https://github.com/you0708/lznt1/blob/master/lznt1.py
def _decompress_chunk(chunk):
    out = bytes()
    while chunk:
        flags = ord(chunk[0:1])
        chunk = chunk[1:]
        for i in range(8):
            if not (flags >> i & 1):
                out += chunk[0:1]
                chunk = chunk[1:]
            else:
                flag = struct.unpack('<H', chunk[:2])[0]
                pos = len(out) - 1
                l_mask = 0xFFF
                o_shift = 12
                while pos >= 0x10:
                    l_mask >>= 1
                    o_shift -= 1
                    pos >>= 1

                length = (flag & l_mask) + 3
                offset = (flag >> o_shift) + 1

                if length >= offset:
                    tmp = out[-offset:] * int(0xFFF / len(out[-offset:]) + 1)
                    out += tmp[:length]
                else:
                    out += out[-offset:-offset+length]
                chunk = chunk[2:]
            if len(chunk) == 0:
                break
    return out

# Usage of LZNT1 decompress function code from https://github.com/you0708/lznt1/blob/master/lznt1.py
def decompress(buf, length_check=True):
    out = bytes()
    while buf:
        header = struct.unpack('<H', buf[:2])[0]
        length = (header & 0xFFF) + 1
        if length_check and length > len(buf[2:]):
            raise ValueError('invalid chunk length')
        else:
            chunk = buf[2:2+length]
            if header & 0x8000:
                out += _decompress_chunk(chunk)
            else:
                out += chunk
        buf = buf[2+length:]

    return out

def search_offset_data_section(file):
    offset = 0
    pe = pefile.PE(file)
    for section in pe.sections:
        if ".data" in str(section.Name):
            offset = section.PointerToRawData
            return offset

    return offset

def search_offset_packer_header(file, offset):
    p = re.compile(b'\x00\x00\x00\x00([\x01-\xff]+)\x01')
    file.seek(offset)
    search_header = file.read(768)
    start = p.search(search_header)

    if(start):
        start = start.start()
        print("Packer header found")
        offset = offset+start
        return offset
    else:
        print("header not found. Consider finding it manually and pass it as an arg in this script")
        exit()
def extract_header_info(file, offset):
    file.seek(offset+4)
    first_key = file.read(1)
    first_key = int.from_bytes(first_key)
    print("XOR key for first iteration : "+hex(first_key))

    file.seek(offset+26)
    second_key = file.read(1)
    second_key = int.from_bytes(second_key)
    print("XOR key for second iteration : "+hex(second_key))

    file.seek(offset+17)
    compressed_buffer_size = file.read(4)
    compressed_buffer_size = int.from_bytes(compressed_buffer_size, 'little')
    print("Size of compressed data (in bytes): "+str(compressed_buffer_size))

    file.seek(offset+21)
    uncompressed_buffer_size = file.read(4)
    uncompressed_buffer_size = int.from_bytes(uncompressed_buffer_size, 'little')
    print("Size of uncompressed data (in bytes): "+str(uncompressed_buffer_size))

    file.seek(offset+40)
    compressed_data = file.read(compressed_buffer_size)

    return(first_key, second_key, compressed_buffer_size, uncompressed_buffer_size, compressed_data)

def unpack(first_key, second_key, compressed_data, compressed_buffer_size, uncompressed_buffer_size):

    for i in range(compressed_buffer_size):
        compressed_data[i] = int(first_key) ^ compressed_data[i]

    decompressed = decompress(compressed_data)
    decompressed = bytearray(decompressed)

    for i in range(uncompressed_buffer_size):
        decompressed[i] = int(second_key) ^ decompressed[i]

    return decompressed

def check_unpack_is_pe(decompressed):
    p = re.compile(b'\x4d\x5a')
    start = p.search(decompressed[:2])
    return start

def main():
    parser = argparse.ArgumentParser(description='Unpacker for PackXOR')
    parser.add_argument("--file", help="Packed Malware")
    parser.add_argument("--offset", help="offset of the packed header (in hexadecimal). No prefix (0x, \\x, etc)")
    args = parser.parse_args()

    if(not args.file):
       print("Please provide a file with --file")
       exit()

    if(not args.offset):
        print("Offset header not provided as an argument. Trying to find it anyway.")
        offset = search_offset_data_section(args.file)
        if(offset == 0):
            print(".data section doesn't exist. Unpacking aborted")
            exit()
    else:
        offset = int(args.offset, base=16)


    with open(args.file, 'rb') as fp:
        if(not args.offset):
            offset = search_offset_packer_header(fp, offset)
        first_key, second_key, compressed_buffer_size, uncompressed_buffer_size, compressed_data = extract_header_info(fp, offset)

    compressed_data = bytearray(compressed_data)
    decompressed = unpack(first_key, second_key, compressed_data, compressed_buffer_size, uncompressed_buffer_size)
    is_success = check_unpack_is_pe(decompressed)

    if(is_success):
        print("Unpacking SUCCESS")
        with open(args.file.replace(".exe","_unpacked.exe"), 'wb') as fp:
            fp.write(decompressed)
        print("Unpacked file available in "+args.file.replace(".exe","_unpacked.exe"))
    else:
        print("Unpacking FAILED")

if __name__ == '__main__':
    main()
