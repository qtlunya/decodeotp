# decodeotp

Extract TOTP/HOTP secret keys from Google Authenticator exports

## Installation
1. Install the dependencies: `pip install -r requirements.txt`
2. Install the Protocol Buffers Compiler (protoc)
3. Generate a Python file out of the `.proto` schema: `protoc --python_out=. google_auth.proto`

## Usage
1. Export your accounts from Google Authenticator
2. Screenshot the QR code and decode it 
3. Pass the URL to the script: `./decodeotp.py "otpauth-migration://offline?data=..."`

The output will be in form of `otpauth://` URLs, one per line, like this:
```
otpauth://totp/ACME%20Inc.:John%20Smith?secret=ABCDEFGHIJKLMNOP&issuer=ACME%20Inc.&algorithm=SHA1&digits=6
```

## License
[MIT License](LICENSE)

`google_auth.proto` is provided by the [Aegis](https://github.com/beemdevelopment/Aegis) project. All other files contain original code.
