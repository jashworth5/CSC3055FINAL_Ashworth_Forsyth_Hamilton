# Secure Intrusion Detection and Alert System (IDS)

## Team Member
- David Hamilton

## Overview
This project implements a secure Intrusion Detection System (IDS) that includes:
- CHAP and TOTP-based multi-factor authentication
- Secure AES-encrypted communication
- Session key management
- Replay protection using nonces and timestamps
- JSON-based protocol messages
- Tamper-evident alert logging on the server

## How to Use

### Server
```bash
java -cp ".;lib/bcprov.jar;lib/merrimackutil.jar" server.Server
