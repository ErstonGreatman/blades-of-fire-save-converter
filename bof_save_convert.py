#!/usr/bin/env python3
"""
Blades of Fire save converter (Epic Games <-> Steam).

Converts Profile.BoF between the Epic Games Store and Steam versions of the game.
Runs on Windows, Linux (incl. Proton/Steam Deck) and macOS with plain Python 3.6+;
no third-party packages needed. If `cryptography` or `pycryptodome` is installed it
is used automatically for speed, otherwise a built-in pure-Python AES is used.

Profile.BoF layout (identical on both platforms for the same game build):
  0x0000-0x2027    plain header ("RGMH", version, GUID, "Mercury Engine")
  0x2028-0x102047  AES-256-CBC (zero IV, no padding) payload of 0x100020 bytes:
                     +0x000000  "0002", uint32 LZ4 compressed size, LZ4 block (save data)
                     +0x100000  SHA-256 of the first 0x100000 bytes, each byte XOR 0x01

The AES key is BASE_KEY (64 hex digits) with the platform user-ID string written over
its start, then hex-decoded:
  Steam : no ID is mixed in, the base key is used unchanged
  Epic  : the 32-hex-char Epic account ID (the save folder name) replaces the first 32 digits

The decrypted contents hold no platform IDs, so converting is decrypt-with-source-key,
encrypt-with-target-key. The source file is never modified.

Usage:
  python3 bof_save_convert.py SOURCE DESTINATION
SOURCE / DESTINATION are save folders (named after the account ID) or Profile.BoF paths.
"""
import argparse
import hashlib
import os
import re
import shutil
import struct
import sys
import time

BASE_KEY = "c458429a015d51ed12616515526ee3004bb3dad22345547d94146d2e3dc172eb"
HEADER_SIZE = 0x2028
PAYLOAD_SIZE = 0x100020
BODY_SIZE = 0x100000
FILE_SIZE = HEADER_SIZE + PAYLOAD_SIZE
ZERO_IV = bytes(16)


# --------------------------------------------------------------------------------------------
# AES-256-CBC: use a fast library if present, else a pure-Python table implementation.
# --------------------------------------------------------------------------------------------
def _backend():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def run(key, data, encrypt):
            c = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV))
            op = c.encryptor() if encrypt else c.decryptor()
            return op.update(data) + op.finalize()
        return "cryptography", run
    except ImportError:
        pass
    try:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            from Cryptodome.Cipher import AES

        def run(key, data, encrypt):
            c = AES.new(key, AES.MODE_CBC, iv=ZERO_IV)
            return c.encrypt(data) if encrypt else c.decrypt(data)
        return "pycryptodome", run
    except ImportError:
        pass
    return "built-in (pure Python, slower)", _PyAES.cbc


class _PyAES:
    """Table-driven AES (FIPS-197) for 256-bit keys, CBC mode, no padding."""
    _ready = False

    @classmethod
    def _init(cls):
        if cls._ready:
            return

        def xt(a):
            a <<= 1
            return (a ^ 0x11B) if a & 0x100 else a

        def mul(a, b):
            r = 0
            while b:
                if b & 1:
                    r ^= a
                a = xt(a)
                b >>= 1
            return r

        sbox = [0] * 256
        for x in range(256):
            inv = 0
            if x:
                inv = next(y for y in range(1, 256) if mul(x, y) == 1)
            s = inv
            for i in range(1, 5):
                s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
            sbox[x] = s ^ 0x63
        inv_sbox = [0] * 256
        for i, s in enumerate(sbox):
            inv_sbox[s] = i

        def ror(w, n):
            return ((w >> n) | (w << (32 - n))) & 0xFFFFFFFF

        te0 = [(mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3) for s in sbox]
        td0 = [(mul(s, 14) << 24) | (mul(s, 9) << 16) | (mul(s, 13) << 8) | mul(s, 11) for s in inv_sbox]
        cls.sbox, cls.inv_sbox = sbox, inv_sbox
        cls.te = [te0] + [[ror(w, 8 * k) for w in te0] for k in (1, 2, 3)]
        cls.td = [td0] + [[ror(w, 8 * k) for w in td0] for k in (1, 2, 3)]
        cls._ready = True

    @classmethod
    def _expand(cls, key):
        sbox = cls.sbox
        w = list(struct.unpack(">8I", key))
        rcon = 1
        for i in range(8, 60):
            t = w[i - 1]
            if i % 8 == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (sbox[t >> 24] << 24) | (sbox[(t >> 16) & 255] << 16) | (sbox[(t >> 8) & 255] << 8) | sbox[t & 255]
                t ^= rcon << 24
                rcon = (rcon << 1) ^ (0x11B if rcon & 0x80 else 0)
            elif i % 8 == 4:
                t = (sbox[t >> 24] << 24) | (sbox[(t >> 16) & 255] << 16) | (sbox[(t >> 8) & 255] << 8) | sbox[t & 255]
            w.append(w[i - 8] ^ t)
        enc = w
        # Equivalent inverse cipher key schedule.
        dec = []
        for r in range(14, -1, -1):
            rk = w[4 * r:4 * r + 4]
            if 0 < r < 14:
                d0, d1, d2, d3 = cls.td
                rk = [d0[sbox[x >> 24]] ^ d1[sbox[(x >> 16) & 255]] ^ d2[sbox[(x >> 8) & 255]] ^ d3[sbox[x & 255]] for x in rk]
            dec.extend(rk)
        return enc, dec

    @classmethod
    def cbc(cls, key, data, encrypt):
        cls._init()
        enc, dec = cls._expand(key)
        n = len(data) // 4
        words = struct.unpack(">%dI" % n, data)
        out = [0] * n
        sb, isb = cls.sbox, cls.inv_sbox
        p0 = p1 = p2 = p3 = 0  # IV (all zero)
        if encrypt:
            T0, T1, T2, T3 = cls.te
            rk = enc
            for b in range(0, n, 4):
                s0 = words[b] ^ p0 ^ rk[0]
                s1 = words[b + 1] ^ p1 ^ rk[1]
                s2 = words[b + 2] ^ p2 ^ rk[2]
                s3 = words[b + 3] ^ p3 ^ rk[3]
                k = 4
                for _ in range(13):
                    t0 = T0[s0 >> 24] ^ T1[(s1 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s3 & 255] ^ rk[k]
                    t1 = T0[s1 >> 24] ^ T1[(s2 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s0 & 255] ^ rk[k + 1]
                    t2 = T0[s2 >> 24] ^ T1[(s3 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s1 & 255] ^ rk[k + 2]
                    t3 = T0[s3 >> 24] ^ T1[(s0 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s2 & 255] ^ rk[k + 3]
                    s0, s1, s2, s3 = t0, t1, t2, t3
                    k += 4
                p0 = ((sb[s0 >> 24] << 24) | (sb[(s1 >> 16) & 255] << 16) | (sb[(s2 >> 8) & 255] << 8) | sb[s3 & 255]) ^ rk[56]
                p1 = ((sb[s1 >> 24] << 24) | (sb[(s2 >> 16) & 255] << 16) | (sb[(s3 >> 8) & 255] << 8) | sb[s0 & 255]) ^ rk[57]
                p2 = ((sb[s2 >> 24] << 24) | (sb[(s3 >> 16) & 255] << 16) | (sb[(s0 >> 8) & 255] << 8) | sb[s1 & 255]) ^ rk[58]
                p3 = ((sb[s3 >> 24] << 24) | (sb[(s0 >> 16) & 255] << 16) | (sb[(s1 >> 8) & 255] << 8) | sb[s2 & 255]) ^ rk[59]
                out[b], out[b + 1], out[b + 2], out[b + 3] = p0, p1, p2, p3
        else:
            T0, T1, T2, T3 = cls.td
            rk = dec
            for b in range(0, n, 4):
                c0, c1, c2, c3 = words[b], words[b + 1], words[b + 2], words[b + 3]
                s0, s1, s2, s3 = c0 ^ rk[0], c1 ^ rk[1], c2 ^ rk[2], c3 ^ rk[3]
                k = 4
                for _ in range(13):
                    t0 = T0[s0 >> 24] ^ T1[(s3 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s1 & 255] ^ rk[k]
                    t1 = T0[s1 >> 24] ^ T1[(s0 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s2 & 255] ^ rk[k + 1]
                    t2 = T0[s2 >> 24] ^ T1[(s1 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s3 & 255] ^ rk[k + 2]
                    t3 = T0[s3 >> 24] ^ T1[(s2 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s0 & 255] ^ rk[k + 3]
                    s0, s1, s2, s3 = t0, t1, t2, t3
                    k += 4
                out[b] = ((isb[s0 >> 24] << 24) | (isb[(s3 >> 16) & 255] << 16) | (isb[(s2 >> 8) & 255] << 8) | isb[s1 & 255]) ^ rk[56] ^ p0
                out[b + 1] = ((isb[s1 >> 24] << 24) | (isb[(s0 >> 16) & 255] << 16) | (isb[(s3 >> 8) & 255] << 8) | isb[s2 & 255]) ^ rk[57] ^ p1
                out[b + 2] = ((isb[s2 >> 24] << 24) | (isb[(s1 >> 16) & 255] << 16) | (isb[(s0 >> 8) & 255] << 8) | isb[s3 & 255]) ^ rk[58] ^ p2
                out[b + 3] = ((isb[s3 >> 24] << 24) | (isb[(s2 >> 16) & 255] << 16) | (isb[(s1 >> 8) & 255] << 8) | isb[s0 & 255]) ^ rk[59] ^ p3
                p0, p1, p2, p3 = c0, c1, c2, c3
        return struct.pack(">%dI" % n, *out)


BACKEND_NAME, aes_cbc = _backend()


# --------------------------------------------------------------------------------------------
# Save handling
# --------------------------------------------------------------------------------------------
class SaveError(Exception):
    pass


def resolve(path):
    """Return (Profile.BoF path, account-ID folder name) for a folder or file argument."""
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isdir(path) or not path.lower().endswith(".bof"):
        folder, file = path, os.path.join(path, "Profile.BoF")
    else:
        folder, file = os.path.dirname(path), path
    return file, os.path.basename(os.path.normpath(folder))


def key_prefix(account_id):
    """Epic IDs (32 hex chars) are mixed into the key; Steam uses the base key unchanged."""
    if re.fullmatch(r"[0-9a-fA-F]{32}", account_id):
        return account_id
    if account_id == "" or re.fullmatch(r"\d{17}", account_id):
        return ""
    raise SaveError("Can't tell whether %r is a Steam ID (17 digits) or an Epic ID (32 hex chars); "
                    "pass --source-id / --target-id." % account_id)


def make_key(prefix):
    return bytes.fromhex(prefix + BASE_KEY[len(prefix):])


def platform_name(prefix):
    return "Epic (%s)" % prefix if prefix else "Steam"


def is_valid_plaintext(plain):
    if plain[:4] != b"0002":
        return False
    digest = hashlib.sha256(plain[:BODY_SIZE]).digest()
    return len({a ^ b for a, b in zip(digest, plain[BODY_SIZE:])}) == 1


def read_save(file):
    if not os.path.isfile(file):
        raise SaveError("Save not found: %s" % file)
    with open(file, "rb") as f:
        data = f.read()
    if len(data) != FILE_SIZE:
        raise SaveError("Unexpected size %d for %s (expected %d)." % (len(data), file, FILE_SIZE))
    if data[:4] != b"RGMH":
        raise SaveError("%s is not a Blades of Fire save (missing RGMH header)." % file)
    return data


def decrypt_save(data, candidates):
    payload = data[HEADER_SIZE:]
    for prefix in candidates:
        key = make_key(prefix)
        # Cheap check on the first block before decrypting the whole megabyte.
        if aes_cbc(key, payload[:16], False)[:4] != b"0002":
            continue
        plain = aes_cbc(key, payload, False)
        if is_valid_plaintext(plain):
            return prefix, plain
    return None, None


def convert(source, destination, source_id=None, target_id=None, backup=True, log=print):
    src_file, src_folder_id = resolve(source)
    dst_file, dst_folder_id = resolve(destination)
    if os.path.normcase(src_file) == os.path.normcase(dst_file):
        raise SaveError("Source and destination are the same file.")

    data = read_save(src_file)
    if source_id is not None:
        candidates = [key_prefix(source_id)]
    else:
        candidates = []
        try:
            candidates.append(key_prefix(src_folder_id))
        except SaveError:
            pass
        if "" not in candidates:
            candidates.append("")
    src_prefix, plain = decrypt_save(data, candidates)
    if plain is None:
        raise SaveError("Could not decrypt %s with any known key; try --source-id <account id>." % src_file)
    log("Decrypted source  : %s  [%s key]" % (src_file, platform_name(src_prefix)))

    tgt_prefix = key_prefix(target_id if target_id is not None else dst_folder_id)
    tgt_key = make_key(tgt_prefix)
    out = data[:HEADER_SIZE] + aes_cbc(tgt_key, plain, True)
    if aes_cbc(tgt_key, out[HEADER_SIZE:], False) != plain:
        raise SaveError("Internal error: re-encrypted save failed verification. Nothing was written.")

    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
    if backup and os.path.exists(dst_file):
        bak = "%s.bak-%s" % (dst_file, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(dst_file, bak)
        log("Backed up existing: %s" % bak)
    tmp = dst_file + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, dst_file)
    log("Wrote destination : %s  [%s key]" % (dst_file, platform_name(tgt_prefix)))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Convert Blades of Fire saves (Profile.BoF) between the Epic Games and Steam versions.",
        epilog="SOURCE/DESTINATION are save folders named after the account ID (e.g. "
               "76561198000000000 for Steam, a 32-hex-char ID for Epic) or Profile.BoF paths inside them. "
               "Windows saves live in %%LOCALAPPDATA%%\\MercurySteam\\Blades of Fire; under Proton look in "
               "steamapps/compatdata/<appid>/pfx/drive_c/users/steamuser/AppData/Local/MercurySteam/Blades of Fire.")
    ap.add_argument("source", help="source save folder or Profile.BoF")
    ap.add_argument("destination", help="destination save folder or Profile.BoF")
    ap.add_argument("--source-id", help="account ID for the source key (default: source folder name, then Steam)")
    ap.add_argument("--target-id", help="account ID for the destination key (default: destination folder name)")
    ap.add_argument("--no-backup", action="store_true", help="don't back up an existing destination Profile.BoF")
    args = ap.parse_args(argv)

    print("AES backend       : %s" % BACKEND_NAME)
    try:
        convert(args.source, args.destination, args.source_id, args.target_id, not args.no_backup)
    except SaveError as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
