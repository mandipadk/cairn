//! Outbound mail, by handing a finished message to a command.
//!
//! The forge does not speak SMTP itself. Whoever runs it names a command
//! that reads one RFC 5322 message on stdin - `sendmail -t`, `msmtp -t`,
//! anything that behaves like them - and the forge writes to it. That is
//! the oldest contract there is for this, it needs no credentials in
//! this process, and it means a failure to send is that command's exit
//! status rather than a guess.

use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct Mailer {
    /// Run through `sh -c`, so a configured value may carry arguments.
    command: String,
    from: String,
}

impl Mailer {
    pub fn command(command: impl Into<String>, from: impl Into<String>) -> Self {
        Mailer {
            command: command.into(),
            from: from.into(),
        }
    }

    /// Send one plain-text message. Blocking, and meant to be called
    /// from a blocking context: a reset request is rare and the command
    /// is expected to hand off quickly.
    pub fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        // Header values are single lines; anything a caller passes that
        // is not becomes one, so no header can be injected through them.
        let clean = |s: &str| s.replace(['\r', '\n'], " ");
        let message = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n",
            clean(&self.from),
            clean(to),
            clean(subject),
            jiff::Timestamp::now().strftime("%a, %d %b %Y %H:%M:%S %z"),
            body
        );
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&self.command)
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
