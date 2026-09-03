//! Outbound mail.
//!
//! The ordinary way is SMTP to a relay, the forge's own or a provider's,
//! given as one URL with the credentials in it, the way every deploy tool
//! already expects. The other way hands a finished message to a command
//! such as `sendmail -t`, for machines that already have a mail system
//! and would rather not put credentials in one more place.

use lettre::message::header::ContentType;
use lettre::transport::smtp::SmtpTransport;
use lettre::{Message, Transport};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone)]
pub enum Mailer {
    Smtp {
        transport: SmtpTransport,
        from: String,
    },
    Command {
        command: String,
        from: String,
    },
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the URL: it carries a password.
        match self {
            Mailer::Smtp { from, .. } => write!(f, "Mailer::Smtp(from {from})"),
            Mailer::Command { command, from } => {
                write!(f, "Mailer::Command({command:?}, from {from})")
            }
        }
    }
}

impl Mailer {
    /// `smtps://user:pass@host:465` for SMTP over TLS, or
    /// `smtp://user:pass@host:587?tls=required` for STARTTLS. Anything
    /// unencrypted is refused: a password reset link is a credential.
    pub fn smtp(url: &str, from: impl Into<String>) -> Result<Self, String> {
        let plain = url.starts_with("smtp://") && !url.contains("tls=required");
        if plain {
            return Err(
                "an smtp:// URL must carry ?tls=required; use smtps:// for TLS on connect".into(),
            );
        }
        let transport = SmtpTransport::from_url(url)
            .map_err(|e| format!("cannot read the SMTP URL: {e}"))?
            .build();
        Ok(Mailer::Smtp {
            transport,
            from: from.into(),
        })
    }

    /// For a log line: how mail goes out, never the credentials.
    pub fn describe(&self) -> String {
        match self {
            Mailer::Smtp { from, .. } => format!("SMTP relay, sending as {from}"),
            Mailer::Command { command, from } => format!("command {command:?}, sending as {from}"),
        }
    }

    pub fn command(command: impl Into<String>, from: impl Into<String>) -> Self {
        Mailer::Command {
            command: command.into(),
            from: from.into(),
        }
    }

    /// Prove the configuration without sending anyone anything: connect
    /// to the relay, negotiate TLS and authenticate, then hang up; or
    /// confirm the command exists. What it returns is what a real send
    /// would have hit first.
    pub fn check(&self) -> Result<String, String> {
        match self {
            Mailer::Smtp { transport, from } => transport
                .test_connection()
                .map_err(|e| format!("the relay refused the connection: {e}"))
                .and_then(|ok| {
                    if ok {
                        Ok(format!(
                            "relay reached, TLS and authentication accepted; sending as {from}"
                        ))
                    } else {
                        Err("the relay did not answer the handshake".to_owned())
                    }
                }),
            Mailer::Command { command, from } => {
                let program = command.split_whitespace().next().unwrap_or_default();
                let found = Command::new("sh")
                    .arg("-c")
                    .arg(format!("command -v {program}"))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if found {
                    Ok(format!("{program} is on PATH; sending as {from}"))
                } else {
                    Err(format!("{program} is not on PATH"))
                }
            }
        }
    }

    /// Send one plain-text message. Blocking; call it off the runtime.
    pub fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        match self {
            Mailer::Smtp { transport, from } => {
                let message = Message::builder()
                    .from(from.parse().map_err(|e| format!("bad From address: {e}"))?)
                    .to(to.parse().map_err(|e| format!("bad To address: {e}"))?)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body.to_owned())
                    .map_err(|e| format!("cannot build the message: {e}"))?;
                transport
                    .send(&message)
                    .map(|_| ())
                    .map_err(|e| format!("the relay refused the message: {e}"))
            }
            Mailer::Command { command, from } => {
                let clean = |s: &str| s.replace(['\r', '\n'], " ");
                let message = format!(
                    "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMIME-Version: 1.0\r\n\
                     Content-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n",
                    clean(from),
                    clean(to),
                    clean(subject),
                    jiff::Timestamp::now().strftime("%a, %d %b %Y %H:%M:%S %z"),
                    body
                );
                let mut child = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("cannot start the mail command: {e}"))?;
                child
                    .stdin
                    .take()
                    .ok_or("no stdin on the mail command")?
                    .write_all(message.as_bytes())
                    .map_err(|e| format!("cannot write to the mail command: {e}"))?;
                let output = child
                    .wait_with_output()
                    .map_err(|e| format!("mail command did not finish: {e}"))?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err(format!(
                        "mail command exited {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Mailer;

    #[test]
    fn only_encrypted_smtp_is_accepted() {
        assert!(Mailer::smtp("smtps://u:p@smtp.example.com:465", "f@example.com").is_ok());
        assert!(
            Mailer::smtp(
                "smtp://u:p@smtp.example.com:587?tls=required",
                "f@example.com"
            )
            .is_ok()
        );
        assert!(Mailer::smtp("smtp://u:p@smtp.example.com:587", "f@example.com").is_err());
        assert!(Mailer::smtp("not a url", "f@example.com").is_err());
    }
}
