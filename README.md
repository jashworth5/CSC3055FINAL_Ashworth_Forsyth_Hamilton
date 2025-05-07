# Secure Intrusion Detection and Alert System (IDS)

## Team Member
- Jack Ashworth
- Owen Forsyth
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

### Server Setup

Compile and run:

javac *.java

java Server

Server listens on TCP port 9999

### Client Setup

Compile and run:

javac *.java

java client.ClientGUI

Login with test users (alice:123, bob:456) and correct TOTP

Submit alerts or perform port scans via GUI
