import hashlib
import yaml
import os
import struct
from os import urandom
from Crypto.Cipher import AES
from Crypto.Util import Counter

def pad(t, l):
    t += b";"
    while len(t) < l:
        a = urandom(1)
        if a[0] < 128 and a != b'\n':
            t += a
    return t

def aes_encrypt(plain_text, key, nonce):
    ctr = Counter.new(128, initial_value=int.from_bytes(nonce, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plain_text)

def generate_check_command(desc, key, nonce):
    encrypted = aes_encrypt(pad(desc, 100), key, nonce)
    return f"check(\"{encrypted.hex()}\");".encode()

def process_yaml(filename):
    with open(filename, "r") as file:
        config = yaml.safe_load(file)

    prefix = config.get("prefix", "42042042").encode()
    report_path = config.get("report_path", "/opt/scoring/ScoringReport.html").encode()
    salt = bytes.fromhex(config.get("salt", "0123456789abcdef"))

    assert len(prefix) == 8, "Prefix must be 8 bytes long"
    assert len(salt) == 8, "Salt must be 8 bytes long"

    out = b""
    nvulns = 0
    nchecks = 0
    maxpoints = 0

    for check_id, entry in enumerate(config.get("checks", [])):
        desc_text = entry["description"].encode()
        assert len(desc_text) < 100, "Maximum description length is 100 bytes."

        desc = prefix + struct.pack("<I", len(desc_text)) + \
                        struct.pack("<I", entry["points"]) + \
                        struct.pack("<I", check_id) + \
                        desc_text

        if entry["type"].lower() == "filecontains":
            key_data = entry["filename"].encode()
            key_data += b":" + entry["line"].strip().lower().replace(" ", "").encode()
        elif entry["type"].lower() == "fileexists":
            key_data = entry["filename"].encode()
        elif entry["type"].lower() == "userexists":
            key_data = b"user:" + entry["user"].strip().encode()
        elif entry["type"].lower() == "groupexists":
            key_data = b"group:" + entry["group"].strip().encode()
        elif entry["type"].lower() == "serviceup":
            key_data = b"/run/systemd/units/invocation:" + entry["service"].strip().encode() + b".service"
        elif entry["type"].lower() in ["owneruid", "ownergid"]:
            key_data = entry["filename"].encode()
            key_data += b":" + (b"us:" if entry["type"].lower() == "owneruid" else b"gr:") + entry["id"].encode()
        elif entry["type"].lower() in ["worldwritable", "worldreadable", "stickybit", "suid", "sgid"]:
            key_data = entry["filename"].encode()
            lookup = {"worldwritable": "ow", "worldreadable": "or", "stickybit": "sb", "suid": "su", "sgid": "sg"}
            key_data += b":" + lookup[entry["type"].lower()].encode() + b":" + entry["value"].encode()

        nonce = b"\0"*16 # unconventional use of aes-ctr, nonce can be the same because key is always different
        key = hashlib.sha256(salt + key_data).digest()
        out += b"    " + generate_check_command(desc, key, nonce) + b" \\\n"
        if entry["points"] >= 0: # penalties
          nvulns += 1
        nchecks += 1
        maxpoints += entry["points"]

    with open("config.h", "wb") as output_file:
        output_file.write(f'#define SALT "{salt.hex()}"\n'.encode())
        output_file.write(f'#define MAGIC "{prefix.decode()}"\n'.encode())
        output_file.write(f'#define NUM_VULNS {nvulns}\n'.encode())
        output_file.write(f'#define NUM_CHECKS {nchecks}\n'.encode())
        output_file.write(f'#define MAX_POINTS {maxpoints}\n'.encode())
        output_file.write(f'#define REPORT_PATH "{report_path.decode()}"\n'.encode())
        output_file.write('#define RUN_CHECKS() do { \\'.encode() + b'\n')
        output_file.write(out)
        output_file.write('} while(0)\n'.encode())

    print("Configuration file 'config.h' generated successfully.")

if __name__ == "__main__":
    process_yaml("config.yaml")
