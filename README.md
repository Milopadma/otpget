# OTPGet

A simple command-line tool to extract OTP codes from your email inbox.

## Installation

### Using Cargo (Recommended)
If you have Rust installed, you can install directly using cargo:
```bash
cargo install otpget
```

Don't have Rust? Install it first:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Manual Setup
1. Place the `otpget` binary in a directory of your choice
2. Run the setup wizard:
```bash
./otpget --setup
```
3. Enter your email credentials and IMAP server.
4. You can now run `otpget` without the `--setup` flag.

## Usage

### Single Check
To check the latest emails once for OTP codes:
```bash
./otpget
```

### Continuous Monitoring
To continuously monitor for new OTP codes (checks every 3 seconds):
```bash
./otpget --retry
```
Press Ctrl+C to stop monitoring.

## Supported Email Providers
- Yahoo Mail (default)
- Gmail (use `imap.gmail.com` as IMAP_SERVER)
- Other IMAP-compatible email providers (specify your provider's IMAP server)

## Note
For Gmail users: You'll need to use an App Password instead of your regular password. 
[Generate an App Password here](https://myaccount.google.com/apppasswords) 