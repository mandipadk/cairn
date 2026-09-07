//! Ask a forge whether it is up, remember the answer, and say so by mail
//! when that changes. One invocation is one look; a timer supplies the
//! rhythm, and the state file carries memory between looks so that mail
//! goes out on transitions and once a day while down, never on every tick.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// How long a forge stays down before it is worth saying again.
pub const REMIND_AFTER: i64 = 24 * 3600;

/// What the watcher last saw.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub up: bool,
    /// When the forge was first seen in this condition, in unix seconds.
    pub since: i64,
    /// When mail last went out about this condition, in unix seconds.
    pub mailed: Option<i64>,
    /// What healthz said, or why it could not be asked.
    pub detail: String,
}

/// One look at the forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Up { seq: u64 },
    Down { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub subject: String,
    pub body: String,
}

pub fn probe(agent: &ureq::Agent, url: &str) -> Answer {
    let target = format!("{}/healthz", url.trim_end_matches('/'));
    let mut response = match agent.get(&target).call() {
        Ok(response) => response,
        Err(e) => {
            return Answer::Down {
                reason: format!("{target}: {e}"),
            };
        }
    };
    let status = response.status().as_u16();
    match response.body_mut().read_json::<serde_json::Value>() {
        Ok(v) if status == 200 && v["ok"] == true => Answer::Up {
            seq: v["seq"].as_u64().unwrap_or(0),
        },
        Ok(v) => Answer::Down {
            reason: format!("healthz answered {status}: {v}"),
        },
        Err(e) => Answer::Down {
            reason: format!("healthz answered {status}, not as JSON: {e}"),
        },
    }
}

/// Fold this look into what was seen before, and say whether anyone
/// should hear about it.
pub fn decide(
    previous: Option<&Seen>,
    answer: &Answer,
    now: i64,
    url: &str,
) -> (Seen, Option<Mail>) {
    let (up, detail) = match answer {
        Answer::Up { seq } => (true, format!("healthz ok, seq {seq}")),
        Answer::Down { reason } => (false, reason.clone()),
    };
    match previous {
        Some(p) if p.up == up => {
            let mut seen = p.clone();
            seen.detail = detail;
            let last_word = p.mailed.unwrap_or(p.since);
            if !up && now - last_word >= REMIND_AFTER {
                seen.mailed = Some(now);
                let mail = Mail {
                    subject: format!("{url} is still down"),
                    body: format!(
                        "Down since {} ({}).\n\n{}",
                        human(p.since),
                        ago(now - p.since),
                        seen.detail
                    ),
                };
                (seen, Some(mail))
            } else {
                (seen, None)
            }
        }
        Some(p) => {
            let mail = if up {
                Mail {
                    subject: format!("{url} is back"),
                    body: format!("Up again after {}.\n\n{detail}", ago(now - p.since)),
                }
            } else {
                Mail {
                    subject: format!("{url} is down"),
                    body: format!("Was up since {}.\n\n{detail}", human(p.since)),
                }
            };
            let seen = Seen {
                up,
                since: now,
                mailed: Some(now),
                detail,
            };
            (seen, Some(mail))
        }
        None => {
            let mail = (!up).then(|| Mail {
                subject: format!("{url} is down"),
                body: format!("First look, and it is down.\n\n{detail}"),
            });
            let seen = Seen {
                up,
                since: now,
                mailed: mail.as_ref().map(|_| now),
                detail,
            };
            (seen, mail)
        }
    }
}

/// One look: probe, decide, remember, and mail if there is somebody to
/// tell. Returns what was seen.
pub fn once(
    url: &str,
    state: &Path,
    mail: Option<(&str, &cairn_server::Mailer)>,
) -> anyhow::Result<Seen> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let previous = read_state(state)?;
    let answer = probe(&agent, url);
    let now = jiff::Timestamp::now().as_second();
    let (seen, letter) = decide(previous.as_ref(), &answer, now, url);
    if let (Some(letter), Some((to, mailer))) = (&letter, mail) {
        mailer
            .send(to, &letter.subject, &letter.body)
            .map_err(|e| anyhow::anyhow!("mailing {to}: {e}"))?;
        println!("mailed {to}: {}", letter.subject);
    }
    write_state(state, &seen)?;
    Ok(seen)
}

fn read_state(path: &Path) -> anyhow::Result<Option<Seen>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_state(path: &Path, seen: &Seen) -> anyhow::Result<()> {
    // Written beside and renamed over, so a look interrupted mid-write
    // leaves the last whole answer rather than half of this one.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(seen)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

pub fn human(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .map(|t| t.to_string())
        .unwrap_or_else(|_| unix.to_string())
}

pub fn ago(seconds: i64) -> String {
    let seconds = seconds.max(0);
    match seconds {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://forge.example";

    fn up() -> Answer {
        Answer::Up { seq: 7 }
    }

    fn down() -> Answer {
        Answer::Down {
            reason: "connection refused".into(),
        }
    }

    #[test]
    fn a_forge_first_seen_up_is_not_news() {
        let (seen, mail) = decide(None, &up(), 1000, URL);
        assert!(seen.up && mail.is_none() && seen.mailed.is_none());
        assert_eq!(seen.since, 1000);
    }

    #[test]
    fn going_down_and_coming_back_are_each_said_once() {
        let (was_up, _) = decide(None, &up(), 1000, URL);
        let (now_down, mail) = decide(Some(&was_up), &down(), 2000, URL);
        let mail = mail.expect("going down is news");
        assert_eq!(mail.subject, format!("{URL} is down"));
        assert!(mail.body.contains("connection refused"));
        assert_eq!((now_down.since, now_down.mailed), (2000, Some(2000)));

        let (still_down, quiet) = decide(Some(&now_down), &down(), 2000 + 3600, URL);
        assert!(quiet.is_none(), "an hour down is not said again");
        assert_eq!(still_down.since, 2000, "the outage keeps its start");

        let (back, mail) = decide(Some(&still_down), &up(), 2000 + 7200, URL);
        let mail = mail.expect("coming back is news");
        assert_eq!(mail.subject, format!("{URL} is back"));
        assert!(mail.body.contains("2h 0m"), "{}", mail.body);
        assert!(back.up && back.since == 2000 + 7200);
    }

    #[test]
    fn a_long_outage_is_repeated_once_a_day() {
        let (down_at_0, first) = decide(None, &down(), 0, URL);
        assert!(first.is_some(), "first look down is news");
        let (later, quiet) = decide(Some(&down_at_0), &down(), REMIND_AFTER - 1, URL);
        assert!(quiet.is_none());
        let (reminded, mail) = decide(Some(&later), &down(), REMIND_AFTER, URL);
        let mail = mail.expect("a day down is said again");
        assert_eq!(mail.subject, format!("{URL} is still down"));
        assert_eq!(reminded.mailed, Some(REMIND_AFTER));
        let (_, quiet) = decide(Some(&reminded), &down(), REMIND_AFTER + 60, URL);
        assert!(quiet.is_none(), "the reminder clock restarts");
    }

    #[test]
    fn durations_read_as_people_say_them() {
        assert_eq!(ago(59), "59s");
        assert_eq!(ago(61), "1m");
        assert_eq!(ago(3600 * 5 + 60 * 7), "5h 7m");
        assert_eq!(ago(86_400 * 3 + 3600 * 2), "3d 2h");
    }
}
