#!/usr/bin/env python3
"""Decode Google Authenticator export QR codes into plain OTP secrets.

Google Authenticator's "Transfer accounts" feature packs your accounts into
otpauth-migration:// URLs, shown as one or more QR codes. The data inside is
a base64-encoded protobuf message. This script unpacks it with a tiny
hand-written protobuf reader, so no extra Python packages are needed.
"""

import argparse
import base64
import csv
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from urllib.parse import quote, unquote

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"}

MIGRATION_URL = re.compile(
    r"otpauth-migration://offline\?[^\s\"'<>]*data=[A-Za-z0-9%+/=_-]+"
)

# Enum values from the OtpParameters message in Google's migration proto.
# 0 means "unspecified", which in practice is treated as the default.
ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8}
OTP_TYPES = {0: "totp", 1: "hotp", 2: "totp"}


@dataclass
class Account:
    name: str
    issuer: str
    secret: str
    algorithm: str
    digits: int
    type: str
    counter: int = 0

    @property
    def label(self):
        return f"{self.issuer}:{self.name}" if self.issuer else self.name

    @property
    def uri(self):
        params = [
            f"secret={self.secret}",
            f"algorithm={self.algorithm}",
            f"digits={self.digits}",
        ]
        if self.issuer:
            params.append(f"issuer={quote(self.issuer)}")
        if self.type == "hotp":
            params.append(f"counter={self.counter}")
        else:
            params.append("period=30")
        return f"otpauth://{self.type}/{quote(self.label)}?{'&'.join(params)}"


def warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


# --- protobuf ---------------------------------------------------------------

def _read_varint(buf, pos):
    result = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _iter_fields(buf):
    """Yield (field_number, value) pairs from a protobuf message."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field, wire_type = key >> 3, key & 0x7

        if wire_type == 0:
            value, pos = _read_varint(buf, pos)
        elif wire_type == 2:
            length, pos = _read_varint(buf, pos)
            value = buf[pos:pos + length]
            pos += length
        elif wire_type == 1:
            value = buf[pos:pos + 8]
            pos += 8
        elif wire_type == 5:
            value = buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")

        yield field, value


def _parse_account(buf):
    raw = dict(_iter_fields(buf))
    return Account(
        name=raw.get(2, b"").decode("utf-8", "replace"),
        issuer=raw.get(3, b"").decode("utf-8", "replace"),
        secret=base64.b32encode(raw.get(1, b"")).decode().rstrip("="),
        algorithm=ALGORITHMS.get(raw.get(4, 0), "SHA1"),
        digits=DIGITS.get(raw.get(5, 0), 6),
        type=OTP_TYPES.get(raw.get(6, 0), "totp"),
        counter=raw.get(7, 0),
    )


def decode_migration_url(url):
    """Return (accounts, batch_id, batch_index, batch_size) for one URL."""
    match = re.search(r"data=([^&\s]+)", url)
    if not match:
        raise ValueError("URL has no data parameter")

    # unquote, not unquote_plus: '+' is a legit base64 character here
    data = unquote(match.group(1))
    data += "=" * (-len(data) % 4)
    payload = base64.b64decode(data)

    accounts = []
    batch_id, batch_index, batch_size = 0, 0, 1
    for field, value in _iter_fields(payload):
        if field == 1:
            accounts.append(_parse_account(value))
        elif field == 3:
            batch_size = value
        elif field == 4:
            batch_index = value
        elif field == 5:
            batch_id = value

    return accounts, batch_id, batch_index, batch_size


# --- input sources ----------------------------------------------------------

def read_qr_codes(path):
    """Return the text of every QR code in an image.

    Tries zbarimg first since it's a plain apt install, then pyzbar,
    then OpenCV.
    """
    have_backend = False

    if shutil.which("zbarimg"):
        have_backend = True
        result = subprocess.run(
            ["zbarimg", "--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", path],
            capture_output=True, text=True,
        )
        codes = result.stdout.split()
        if codes:
            return codes

    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
    except ImportError:
        pass
    else:
        have_backend = True
        codes = [c.data.decode("utf-8", "replace") for c in decode(Image.open(path))]
        if codes:
            return codes

    try:
        import cv2
    except ImportError:
        pass
    else:
        have_backend = True
        img = cv2.imread(path)
        if img is not None:
            detector = cv2.QRCodeDetector()
            ok, texts, _, _ = detector.detectAndDecodeMulti(img)
            codes = [t for t in texts if t] if ok else []
            if codes:
                return codes

    if not have_backend:
        raise RuntimeError("no QR decoder found, install zbar-tools or pyzbar")
    return []


def collect_urls(sources):
    urls = []

    for source in sources:
        if source.startswith("otpauth-migration://"):
            urls.append(source)

        elif source == "-":
            if sys.stdin.isatty():
                print("Paste your export URLs, then press Ctrl+D:", file=sys.stderr)
            urls += MIGRATION_URL.findall(sys.stdin.read())

        elif not os.path.isfile(source):
            warn(f"{source}: no such file")

        elif os.path.splitext(source)[1].lower() in IMAGE_EXTENSIONS:
            try:
                codes = read_qr_codes(source)
            except RuntimeError as e:
                warn(f"{source}: {e}")
                continue
            found = [c for c in codes if c.startswith("otpauth-migration://")]
            if not found:
                warn(f"{source}: no Google Authenticator QR code found")
            urls += found

        else:
            with open(source, encoding="utf-8", errors="replace") as f:
                found = MIGRATION_URL.findall(f.read())
            if not found:
                warn(f"{source}: no otpauth-migration URLs found")
            urls += found

    # the same QR might come in twice (e.g. image + pasted URL)
    return list(dict.fromkeys(urls))


# --- output -----------------------------------------------------------------

def print_account(acc):
    print(acc.label)
    print(f"  secret:  {acc.secret}")
    print(f"  type:    {acc.type.upper()}, {acc.algorithm}, {acc.digits} digits")
    print(f"  uri:     {acc.uri}")
    print()


def write_csv(path, accounts):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "issuer", "secret", "type", "algorithm", "digits", "uri"])
        for acc in accounts:
            writer.writerow([acc.name, acc.issuer, acc.secret, acc.type,
                             acc.algorithm, acc.digits, acc.uri])


def main():
    parser = argparse.ArgumentParser(
        description="Decode Google Authenticator export QR codes into OTP secrets.",
        epilog=(
            "examples:\n"
            "  %(prog)s qr1.png qr2.png\n"
            "  %(prog)s export.txt -c accounts.csv\n"
            "  %(prog)s -u qr1.png qr2.png > uris.txt\n"
            "  xclip -o | %(prog)s -"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "sources", nargs="+", metavar="SOURCE",
        help="QR image, text file, otpauth-migration:// URL, or - for stdin",
    )
    parser.add_argument("-c", "--csv", metavar="FILE", help="also save accounts to a CSV file")
    parser.add_argument("-u", "--uris", action="store_true",
                        help="print only otpauth:// URIs, one per line")
    args = parser.parse_args()

    urls = collect_urls(args.sources)
    if not urls:
        print("error: no export URLs found", file=sys.stderr)
        return 1

    accounts = []
    batches = {}  # batch_id -> (batch_size, set of indexes seen)

    for url in urls:
        try:
            found, batch_id, index, size = decode_migration_url(url)
        except (ValueError, IndexError) as e:
            warn(f"could not decode URL: {e}")
            continue
        accounts += found
        batches.setdefault(batch_id, (size, set()))[1].add(index)

    if args.uris:
        for acc in accounts:
            print(acc.uri)
    else:
        for acc in accounts:
            print_account(acc)

    print(f"{len(accounts)} account(s) decoded", file=sys.stderr)

    # Big exports are split across several QR codes. Make it obvious
    # when one of them wasn't included.
    for size, seen in batches.values():
        missing = sorted(set(range(size)) - seen)
        if missing:
            nums = ", ".join(str(i + 1) for i in missing)
            warn(f"export was split into {size} QR codes, missing: {nums}")

    if args.csv:
        write_csv(args.csv, accounts)
        print(f"saved to {args.csv}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
