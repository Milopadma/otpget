use std::env;
use std::thread;
use std::time::Duration;
use native_tls::TlsConnector;
use anyhow::{Result, anyhow};
use mail_parser::Message;
use regex::Regex;
use clap::Parser;
use imap::Session;
use chrono::{Utc, Duration as ChronoDuration};
use dialoguer::{Input, Password, theme::ColorfulTheme};
use keyring::Entry;

const SERVICE_NAME: &str = "otpget";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    retry: bool,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    setup: bool,
}

fn get_credentials() -> Result<(String, String, String)> {
    let email_entry = Entry::new(SERVICE_NAME, "email")?;
    let password_entry = Entry::new(SERVICE_NAME, "password")?;
    let imap_entry = Entry::new(SERVICE_NAME, "imap_server")?;

    let email = email_entry.get_password()
        .map_err(|_| anyhow!("Email not found. Run with --setup flag to configure."))?;
    let password = password_entry.get_password()
        .map_err(|_| anyhow!("Password not found. Run with --setup flag to configure."))?;
    let imap_server = imap_entry.get_password()
        .unwrap_or_else(|_| "imap.mail.yahoo.com".to_string());

    Ok((email, password, imap_server))
}

fn setup_config() -> Result<()> {
    println!("Welcome to OTPGet Setup!");
    println!("This wizard will help you configure your email settings.\n");

    let theme = ColorfulTheme::default();

    let email: String = Input::with_theme(&theme)
        .with_prompt("Enter your email address")
        .interact()?;

    let password: String = Password::with_theme(&theme)
        .with_prompt("Enter your email password")
        .interact()?;

    let imap_server: String = Input::with_theme(&theme)
        .with_prompt("Enter your IMAP server (e.g., imap.gmail.com)")
        .default("imap.gmail.com".into())
        .interact()?;

    // Store credentials in system keyring
    let email_entry = Entry::new(SERVICE_NAME, "email")?;
    let password_entry = Entry::new(SERVICE_NAME, "password")?;
    let imap_entry = Entry::new(SERVICE_NAME, "imap_server")?;

    email_entry.set_password(&email)?;
    password_entry.set_password(&password)?;
    imap_entry.set_password(&imap_server)?;

    println!("\nConfiguration saved securely!");
    println!("You can now run otpget without the --setup flag.");

    Ok(())
}

// debug logging macro
macro_rules! debug {
    ($($arg:tt)*) => {
        if std::env::args().any(|arg| arg == "--debug") {
            println!("debug: {}", format!($($arg)*));
        }
    };
}

fn extract_otp_code(text: &str) -> Option<String> {
    let patterns = [
        r"\b\d{6}\b",                    
        r"code\s*:?\s*(\d{6})",          
        r"password\s*:?\s*(\d{6})",      
        r"otp\s*:?\s*(\d{6})",          
        r"verification\s*code\s*:?\s*(\d{6})"  
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                let otp = caps.get(1).map_or_else(
                    || caps.get(0).unwrap().as_str(),
                    |m| m.as_str()
                );
                return Some(otp.to_string());
            }
        }
    }
    None
}

fn extract_text_from_email(raw_email: &[u8]) -> String {
    let message = Message::parse(raw_email);
    match message {
        Some(msg) => {
            if let Some(text) = msg.body_text(0) {
                return text.to_string();
            }
            
            if let Some(html) = msg.body_html(0) {
                let text = html.replace(|c: char| c == '\n' || c == '\r', " ");
                if let Ok(re) = Regex::new(r"<[^>]*>") {
                    return re.replace_all(&text, "").trim().to_string();
                }
                return text.trim().to_string();
            }
            "No text or HTML content found in email".to_string()
        }
        None => "Could not parse email content".to_string()
    }
}

fn check_latest_email(imap_session: &mut Session<native_tls::TlsStream<std::net::TcpStream>>) -> Result<Option<String>> {
    let _mailbox = imap_session.select("INBOX")?;
    
    // Search for all messages, sorted by date (newest first)
    let uids = imap_session.uid_search("ALL")?;
    
    // Get the messages sorted by internal date
    let sequence = format!("{}:*", uids.iter().min().unwrap_or(&1));
    let messages = imap_session.fetch(sequence, "(INTERNALDATE RFC822)")?;
    
    // Sort messages by internal date
    let mut messages: Vec<_> = messages.iter().collect();
    messages.sort_by_key(|m| m.internal_date().unwrap_or_default());
    messages.reverse(); // newest first
    
    // Get the latest message
    if let Some(message) = messages.first() {
        if let Some(body) = message.body() {
            let clean_text = extract_text_from_email(body);
            return Ok(extract_otp_code(&clean_text));
        }
    }
    
    Ok(None)
}

fn get_latest_messages(imap_session: &mut Session<native_tls::TlsStream<std::net::TcpStream>>, count: u32) -> Result<Vec<String>> {
    let _mailbox = imap_session.select("INBOX")?;
    let mut found_codes = Vec::new();
    
    // Get messages from the last 24 hours
    let date = (Utc::now() - ChronoDuration::days(1)).format("%d-%b-%Y").to_string();
    let search_criteria = format!("SINCE {}", date);
    debug!("searching with criteria: {}", search_criteria);
    
    // Search for recent messages
    let uids = imap_session.uid_search(&search_criteria)?;
    debug!("found {} recent messages", uids.len());
    
    if !uids.is_empty() {
        // Convert to Vec and sort UIDs in descending order to get latest messages first
        let mut uid_vec: Vec<_> = uids.into_iter().collect();
        uid_vec.sort_unstable_by(|a, b| b.cmp(a));
        
        // Take only the latest N messages
        let latest_uids: Vec<_> = uid_vec.iter()
            .take(count as usize)
            .map(|&uid| uid.to_string())
            .collect();
            
        let sequence = latest_uids.join(",");
        debug!("fetching messages with sequence: {}", sequence);
        
        let fetched = imap_session.uid_fetch(sequence, "(INTERNALDATE RFC822)")?;
        debug!("fetched {} messages", fetched.len());
        
        // Sort messages by internal date
        let mut messages: Vec<_> = fetched.iter().collect();
        messages.sort_by_key(|m| m.internal_date().unwrap_or_default());
        messages.reverse(); // newest first
        
        for message in messages {
            if let Some(body) = message.body() {
                let clean_text = extract_text_from_email(body);
                if let Some(otp) = extract_otp_code(&clean_text) {
                    debug!("found otp in message: {}", otp);
                    found_codes.push(otp);
                }
            }
        }
    }
    
    Ok(found_codes)
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    if args.setup {
        return setup_config();
    }

    let (email, password, domain) = get_credentials()?;

    debug!("connecting to {}", domain);
    
    let tls = TlsConnector::builder()
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()?;
    
    let client = imap::connect((domain.as_str(), 993), domain.as_str(), &tls)?;
    
    debug!("attempting login for {}", email);
    
    let mut imap_session = client.login(&email, &password)
        .map_err(|e| {
            debug!("authentication error: {:?}", e);
            e.0
        })?;

    debug!("successfully logged in");

    if args.retry {
        debug!("retry mode enabled - checking for new otp codes every 3 seconds...");
        println!("press ctrl+c to stop");
        let mut last_id = None;
        
        loop {
            if let Ok(Some(otp)) = check_latest_email(&mut imap_session) {
                if Some(&otp) != last_id.as_ref() {
                    println!("found otp code: {}", otp);
                    last_id = Some(otp);
                }
            }
            
            thread::sleep(Duration::from_secs(3));
        }
    } else {
        debug!("fetching latest 10 messages...");
        match get_latest_messages(&mut imap_session, 10) {
            Ok(found_codes) => {
                debug!("found {} otp codes in the latest 10 emails:", found_codes.len());
                println!("found otp codes:");
                for (i, code) in found_codes.iter().enumerate() {
                    println!("{}. {}", i + 1, code);
                }
                
                if found_codes.is_empty() {
                    println!("no otp codes found in any of the messages");
                }
            },
            Err(e) => println!("error fetching messages: {:?}", e),
        }
        
        debug!("logging out");
        imap_session.logout()?;
    }
    
    Ok(())
}
