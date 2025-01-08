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
2. Create a `.env` file in the same directory with your email credentials:
```env
EMAIL=your_email@example.com
PASSWORD=your_email_app_password (not the same as your email password, think api key)
IMAP_SERVER=your.imap.server  # optional, defaults to imap.mail.yahoo.com
```

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