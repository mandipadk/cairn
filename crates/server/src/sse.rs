//! The live event stream: how an agent watches the world.
//!
//! Semantics: every event strictly after the caller's cursor, exactly
//! once, in order, forever — first by catch-up reads from the store,
//! then live from the broadcast bus. The bus is only an optimization;
//! whenever it proves lossy (lag, out-of-order publish between
//! concurrent handlers), the stream heals the gap by re-reading the
//! store. On disconnect, standard SSE `Last-Event-ID` resumes the
//! cursor, so a consumer that remembers nothing but its last-seen id
//! never misses an event.

use crate::auth::Actor;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use cairn_core::{Envelope, EventSeq};
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

const CATCH_UP_BATCH: usize = 500;

#[derive(Deserialize)]
pub struct StreamQuery {
    #[serde(default)]
    pub after: i64,
}

/// Send every stored event after `last` in order; returns whether the
/// receiver is still listening.
async fn drain_from_store(
    app: &AppState,
    who: &cairn_core::PrincipalId,
    tx: &mpsc::Sender<Envelope>,
    last: &mut i64,
) -> Result<bool, cairn_core::CoreError> {
    loop {
        let batch = app.with_store(|s| s.events_after_scoped(EventSeq(*last), CATCH_UP_BATCH))?;
        if batch.is_empty() {
            return Ok(true);
        }
        for scoped in batch {
            // The cursor advances past everything read, sent or not: a
            // reader who cannot see event five must not ask for five
            // again forever.
            *last = scoped.envelope.seq.0;
            let visible = app.with_store(|s| {
                s.scope_visible_to(who, scoped.repo.as_deref(), scoped.subject.as_deref())
            });
            if visible && tx.send(scoped.envelope).await.is_err() {
                return Ok(false);
            }
        }
    }
}

pub async fn stream(
    State(app): State<AppState>,
    actor: Actor,
    Query(query): Query<StreamQuery>,
    headers: HeaderMap,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // Reconnecting clients resume from Last-Event-ID per the SSE spec;
    // first connections use ?after=.
    let cursor = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(query.after);

    let (tx, rx) = mpsc::channel::<Envelope>(64);
    // Subscribe BEFORE catching up, so nothing committed in between is
    // missed; the seq guard below deduplicates the overlap.
    let mut live = app.subscribe();

    let who = actor.0;
    tokio::spawn(async move {
        let mut last = cursor;
        if !drain_from_store(&app, &who, &tx, &mut last)
            .await
            .unwrap_or(false)
        {
            return;
        }
        loop {
            match live.recv().await {
                Ok(envelope) => {
                    if envelope.seq.0 <= last {
                        continue;
                    }
                    // A gap means concurrent handlers published out of
                    // order — the store has the missing events already.
                    if envelope.seq.0 > last + 1 {
                        if !drain_from_store(&app, &who, &tx, &mut last)
                            .await
                            .unwrap_or(false)
                        {
                            return;
                        }
                        continue;
                    }
                    last = envelope.seq.0;
                    // A live event is filtered exactly as a replayed one
                    // is; the cursor still moves past what is withheld.
                    if !app.with_store(|s| s.may_see_event(&who, envelope.seq)) {
                        continue;
                    }
                    if tx.send(envelope).await.is_err() {
                        return;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    if !drain_from_store(&app, &who, &tx, &mut last)
                        .await
                        .unwrap_or(false)
                    {
                        return;
                    }
                }
                Err(RecvError::Closed) => return,
            }
        }
    });

    let events = ReceiverStream::new(rx).map(|envelope| {
        Ok(Event::default()
            .id(envelope.seq.0.to_string())
            .event(envelope.event.kind())
            .data(serde_json::to_string(&envelope).expect("envelopes are always serializable")))
    });
    Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
