# gauth-export-decoder

Get your 2FA secrets back out of Google Authenticator.

Google Authenticator lets you export accounts as QR codes, but those codes use
its own `otpauth-migration://` format that other apps (KeePass, KeePassXC,
Bitwarden, etc.) can't read. This script decodes them into normal Base32
secrets and `otpauth://` URIs you can import anywhere.

Single file, standard library only. QR image reading is optional.

## Setup

```sh
git clone https://github.com/<your-username>/gauth-export-decoder.git
cd gauth-export-decoder
```

To read QR images directly, install a QR decoder. On Debian/Ubuntu/Kali:

```sh
sudo apt install zbar-tools
```

`pyzbar` + `Pillow` or `opencv-python` also work if you'd rather use pip.
If you only feed it text/URLs, you don't need any of these.

## Exporting from Google Authenticator

1. Open Google Authenticator → menu → **Transfer accounts** → **Export accounts**
2. Select the accounts and tap **Next**
3. Screenshot each QR code. If you have more than ~10 accounts, the export is
   split into several codes ("1 of 2", "2 of 2"...). You need all of them.

## Usage

```sh
# QR screenshots
python3 gauth_decode.py qr1.png qr2.png

# a text file with the URLs in it (anywhere in the file, any layout)
python3 gauth_decode.py export.txt

# paste URLs straight into the terminal, finish with Ctrl+D
python3 gauth_decode.py -

# mix and match, and save to CSV
python3 gauth_decode.py qr1.png links.txt -c accounts.csv

# only otpauth:// URIs, one per line
python3 gauth_decode.py -u qr1.png qr2.png
```

Example output:

```
GitHub:alice@example.com
  secret:  JBSWY3DPEHPK3PXP
  type:    TOTP, SHA1, 6 digits
  uri:     otpauth://totp/GitHub%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&...

19 account(s) decoded
```

If a QR code from a multi-part export is missing, you'll get a warning telling
you which one.

## Importing into KeePass

- **KeePassXC:** right-click the entry → TOTP → Set up TOTP, paste the secret.
  Or add the `otpauth://` URI as an attribute named `otp`.
- **KeePass 2.47+:** put the secret in the `TimeOtp-Secret-Base32` field
  (not `TimeOtp-Secret`, which treats it as plain text) and use `{TIMEOTP}`.

If the codes don't match your phone, check your computer's clock and time
zone first. TOTP is time-based, and a wrong time zone is the usual culprit.

## Security

These secrets are your second factor. Anyone who has them can generate your
codes.

- Run this offline, on a machine you trust.
- Don't paste export URLs or upload QR codes to online decoders.
- Delete screenshots, text files and CSVs when you're done.

## License

MIT
