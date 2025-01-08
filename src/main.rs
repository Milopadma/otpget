use std::env;
use std::thread;
use std::time::Duration;
use native_tls::TlsConnector;
use anyhow::Result;
use mail_parser::Message;
use regex::Regex;
use clap::Parser;
use imap::Session;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // enable retry mode - continuously check for new otp codes
    #[arg(long)]
    retry: bool,
}

fn extract_otp_code(text: &str) -> Option<String> {
    // common otp patterns
    let patterns = [
        r"\b\d{6}\b",                    // basic 6 digits
        r"code\s*:?\s*(\d{6})",          // matches "code: 123456" or "code 123456"
        r"password\s*:?\s*(\d{6})",      // matches "password: 123456"
        r"otp\s*:?\s*(\d{6})",          // matches "otp: 123456"
        r"verification\s*code\s*:?\s*(\d{6})"  // matches "verification code: 123456"
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                // If the pattern has a capture group, use it; otherwise use the whole match
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
            // try text content first
            if let Some(text) = msg.body_text(0) {
                return text.to_string();
            }
            
            // fallback to html content if needed
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
    // Get the latest message
    let messages: Vec<_> = imap_session.search("ALL")?.into_iter().collect();
    
    if let Some(&last_id) = messages.last() {
        let sequence = last_id.to_string();
        let messages = imap_session.fetch(sequence, "RFC822")?;
        
        if let Some(message) = messages.iter().next() {
            if let Some(body) = message.body() {
                let clean_text = extract_text_from_email(body);
                return Ok(extract_otp_code(&clean_text));
            }
        }
    }
    
    Ok(None)
}

fn main() -> Result<()> {
    let args = Args::parse();
    dotenv::dotenv().ok();
    
    // get credentials from env vars
    let email = env::var("EMAIL").expect("EMAIL not set");
    let password = env::var("PASSWORD").expect("PASSWORD not set");
    let domain = env::var("IMAP_SERVER").unwrap_or_else(|_| "imap.mail.yahoo.com".to_string());

    println!("debug: connecting to {}", domain);
    
    // setup tls connector with modern settings
    let tls = TlsConnector::builder()
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()?;
    
    let client = imap::connect((domain.as_str(), 993), domain.as_str(), &tls)?;
    
    println!("debug: attempting login for {}", email);
    
    let mut imap_session = client.login(&email, &password)
        .map_err(|e| {
            println!("debug: authentication error: {:?}", e);
            e.0
        })?;

    println!("debug: successfully logged in");

    if args.retry {
        println!("debug: retry mode enabled - checking for new otp codes every 3 seconds...");
        println!("press ctrl+c to stop");
        let mut last_id = None;
        
        loop {
            // refresh inbox view
            let _mailbox = imap_session.select("INBOX")?;
            
            if let Ok(Some(otp)) = check_latest_email(&mut imap_session) {
                // only print new otps
                if Some(&otp) != last_id.as_ref() {
                    println!("found otp code: {}", otp);
                    last_id = Some(otp);
                }
            }
            
            thread::sleep(Duration::from_secs(3));
        }
    } else {
        let mailbox = imap_session.select("INBOX")?;
        println!("debug: total messages in inbox: {}", mailbox.exists);
        
        let messages: Vec<_> = imap_session.search("ALL")?.into_iter().collect();
        let total_messages = messages.len();
        println!("debug: found {} messages", total_messages);
        
        let num_messages_to_fetch = 10.min(total_messages);
        if num_messages_to_fetch > 0 {
            let latest_messages: Vec<_> = messages.into_iter()
                .rev()
                .take(num_messages_to_fetch)
                .collect();
                
            println!("debug: fetching latest {} messages", num_messages_to_fetch);
            
            let sequence = latest_messages
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
                
            let fetched_messages = imap_session.fetch(sequence, "RFC822")?;
            let mut found_codes = Vec::new();
            
            for message in fetched_messages.iter() {
                if let Some(body) = message.body() {
                    let clean_text = extract_text_from_email(body);
                    if let Some(otp) = extract_otp_code(&clean_text) {
                        found_codes.push(otp);
                    }
                }
            }
            
            println!("\ndebug: found {} otp codes in the latest {} emails:", found_codes.len(), num_messages_to_fetch);
            for (i, code) in found_codes.iter().enumerate() {
                println!("{}. {}", i + 1, code);
            }
            
            if found_codes.is_empty() {
                println!("no otp codes found in any of the messages");
            }
        } else {
            println!("no messages found in mailbox");
        }
        
        println!("debug: logging out");
        imap_session.logout()?;
    }
    
    Ok(())
}
