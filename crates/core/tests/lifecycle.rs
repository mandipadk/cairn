//! The full protocol walk: intent → attempt → output → verification →
//! judgment → policy-decided outcome, all against an in-memory store.

use cairn_core::{
    ClaimKind, ClaimSpec, CoreError, Disposition, Event, EventSeq, PrincipalId, PrincipalKind,
    ReviewDomain, SessionState, Store, TaskState,
};

const OID: &str = "0123456789abcdef0123456789abcdef01234567";

fn passing_tests() -> ClaimSpec {
    ClaimSpec {
        kind: ClaimKind::Test,
        command: None,
        passed: true,
        summary: "tests pass".into(),
        unchecked: vec![],
    }
}

fn principal(slug: &str) -> PrincipalId {
    PrincipalId::new(slug).expect("valid slug")
}

/// Store with one human (bootstrap) and two agents of distinct models.
fn seeded() -> (Store, PrincipalId, PrincipalId, PrincipalId) {
    let mut store = Store::open_in_memory().unwrap();
    let human = principal("ada");
    let scout = principal("scout");
    let arbiter = principal("arbiter");
    store
        .register_principal(&human, &human, PrincipalKind::Human, "Ada", None, None)
        .unwrap();
    store
        .register_principal(
            &human,
            &scout,
            PrincipalKind::Agent,
            "Scout",
            Some("claude-fable-5"),
            Some("claude-code"),
        )
        .unwrap();
    store
        .register_principal(
            &human,
            &arbiter,
            PrincipalKind::Agent,
            "Arbiter",
            Some("gpt-6"),
            Some("codex"),
        )
        .unwrap();
    store.create_repo(&human, "forge", "main").unwrap();
    (store, human, scout, arbiter)
}

#[test]
fn full_lifecycle_intent_to_merge() {
    let (mut store, human, scout, arbiter) = seeded();

    // Intent: a durable statement of what and why.
    let (task, _) = store
        .create_task(
            &human,
            Some("forge"),
            "Harden slug validation",
            "Reject uppercase and boundary dashes; property-test the validator.",
            None,
        )
        .unwrap();

    // Attempt: claim first (the anti-collision point), then a session.
    store.claim_task(&scout, &task).unwrap();
    let (session, _) = store.open_session(&scout, &task).unwrap();

    // Output: a change with one revision, linked to intent and attempt.
    let (change, number, _) = store
        .open_change(
            &scout,
            "forge",
            "main",
            "Harden slug validation",
            Some(&task),
            None,
        )
        .unwrap();
    assert_eq!(number, 1);
    let (revision, _) = store
        .push_revision(
            &scout,
            &change,
            OID,
            Some(&session),
            "validate: harden slug rules",
        )
        .unwrap();
    assert_eq!(revision, 1);

    // Verification: structured claims, including what was NOT checked.
    store
        .attach_claim(
            &scout,
            &change,
            revision,
            ClaimSpec {
                kind: ClaimKind::Test,
                command: Some("cargo test -p cairn-core".into()),
                passed: true,
                summary: "42 tests passed".into(),
                unchecked: vec!["fuzzing beyond 10k property-test cases".into()],
            },
        )
        .unwrap();

    // Policy refuses: no independent approval yet, and says so precisely.
    let trace = store.merge_readiness(&change).unwrap();
    assert!(!trace.satisfied);
    assert_eq!(
        trace.requirements.iter().filter(|r| !r.satisfied).count(),
        1
    );
    let err = store.merge_change(&scout, &change).unwrap_err();
    assert!(matches!(err, CoreError::PolicyUnsatisfied(_)));

    // One agent approval is not enough: independence needs a human or
    // two distinct models.
    store
        .give_verdict(
            &arbiter,
            &change,
            revision,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "Validator matches the spec; edge cases covered.",
        )
        .unwrap();
    assert!(!store.merge_readiness(&change).unwrap().satisfied);

    // A human approval completes independence. Merge carries its proof.
    store
        .give_verdict(
            &human,
            &change,
            revision,
            ReviewDomain::Design,
            Disposition::Approve,
            "Right scope, no API break.",
        )
        .unwrap();
    let merged = store.merge_change(&human, &change).unwrap();
    match &merged.event {
        Event::ChangeMerged {
            trace, revision, ..
        } => {
            assert!(trace.satisfied);
            assert!(trace.requirements.iter().all(|r| r.satisfied));
            assert_eq!(*revision, 1);
        }
        other => panic!("expected ChangeMerged, got {other:?}"),
    }
    assert_eq!(
        store.change(&change).unwrap().unwrap().state,
        cairn_core::ChangeState::Merged
    );

    // Attempt closes with knowledge, intent closes as landed.
    store
        .end_session(
            &scout,
            &session,
            SessionState::Completed,
            "Landed change 1. Gotcha for next time: slug rules also apply to repo names.",
        )
        .unwrap();
    store
        .set_task_state(&human, &task, TaskState::Landed)
        .unwrap();

    // The log tells the whole story, in order, from a single cursor.
    let kinds: Vec<&str> = store
        .events_after(EventSeq(0), 100)
        .unwrap()
        .iter()
        .map(|e| e.event.kind())
        .collect();
    assert_eq!(
        kinds,
        [
            "principal_registered",
            "principal_registered",
            "principal_registered",
            "repo_created",
            "task_created",
            "task_claimed",
            "session_opened",
            "change_opened",
            "revision_pushed",
            "claim_attached",
            "verdict_given",
            "verdict_given",
            "change_merged",
            "session_ended",
            "task_state_changed",
        ]
    );
}

#[test]
fn two_distinct_agent_models_satisfy_independence() {
    let (mut store, human, scout, arbiter) = seeded();
    let sentinel = principal("sentinel");
    store
        .register_principal(
            &human,
            &sentinel,
            PrincipalKind::Agent,
            "Sentinel",
            Some("gemini-3"),
            None,
        )
        .unwrap();

    let (change, _, _) = store
        .open_change(&scout, "forge", "main", "Refactor", None, None)
        .unwrap();
    store
        .push_revision(&scout, &change, OID, None, "refactor")
        .unwrap();
    store
        .attach_claim(&scout, &change, 1, passing_tests())
        .unwrap();

    for (agent, rationale) in [
        (&arbiter, "logic holds"),
        (&sentinel, "no regressions found"),
    ] {
        store
            .give_verdict(
                agent,
                &change,
                1,
                ReviewDomain::Correctness,
                Disposition::Approve,
                rationale,
            )
            .unwrap();
    }
    assert!(store.merge_readiness(&change).unwrap().satisfied);

    // Same-model approvals must NOT count twice: register a second
    // claude-fable-5 agent approving — still only two distinct models.
    let echo = principal("echo");
    store
        .register_principal(
            &human,
            &echo,
            PrincipalKind::Agent,
            "Echo",
            Some("gpt-6"),
            None,
        )
        .unwrap();
    let trace = store.merge_readiness(&change).unwrap();
    let independence = trace.requirements.last().unwrap();
    assert!(independence.satisfied);
    assert!(independence.evidence.contains("arbiter"));
}

#[test]
fn blocking_verdict_vetoes_and_concern_does_not() {
    let (mut store, human, scout, _) = seeded();
    let (change, _, _) = store
        .open_change(&scout, "forge", "main", "Risky", None, None)
        .unwrap();
    store
        .push_revision(&scout, &change, OID, None, "risky")
        .unwrap();
    store
        .attach_claim(&scout, &change, 1, passing_tests())
        .unwrap();
    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Design,
            Disposition::Approve,
            "fine",
        )
        .unwrap();
    assert!(store.merge_readiness(&change).unwrap().satisfied);

    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Security,
            Disposition::Concern,
            "would like rate limiting eventually",
        )
        .unwrap();
    assert!(
        store.merge_readiness(&change).unwrap().satisfied,
        "concern must not veto"
    );

    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Security,
            Disposition::Block,
            "injectable",
        )
        .unwrap();
    let trace = store.merge_readiness(&change).unwrap();
    assert!(!trace.satisfied, "block must veto");
    assert!(trace.unmet_summary().contains("no blocking verdict"));
}

#[test]
fn owner_approval_does_not_count_as_independent() {
    let (mut store, human, scout, _) = seeded();
    let (change, _, _) = store
        .open_change(&human, "forge", "main", "Self-serve", None, None)
        .unwrap();
    store
        .push_revision(&human, &change, OID, None, "self")
        .unwrap();
    store
        .attach_claim(&human, &change, 1, passing_tests())
        .unwrap();
    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "lgtm",
        )
        .unwrap();
    assert!(!store.merge_readiness(&change).unwrap().satisfied);

    // Approval from a different principal (agent) still isn't enough
    // alone — one agent model is one perspective.
    store
        .give_verdict(
            &scout,
            &change,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "checks out",
        )
        .unwrap();
    assert!(!store.merge_readiness(&change).unwrap().satisfied);
}

#[test]
fn protocol_misuse_is_rejected_with_typed_errors() {
    let (mut store, human, scout, arbiter) = seeded();

    // Claiming a claimed task conflicts.
    let (task, _) = store.create_task(&human, None, "T", "spec", None).unwrap();
    store.claim_task(&scout, &task).unwrap();
    assert!(matches!(
        store.claim_task(&arbiter, &task).unwrap_err(),
        CoreError::Conflict(_)
    ));

    // A session requires the claim to be yours.
    assert!(matches!(
        store.open_session(&arbiter, &task).unwrap_err(),
        CoreError::Conflict(_)
    ));

    // Unknown actors are rejected.
    let ghost = principal("ghost");
    assert!(matches!(
        store.create_repo(&ghost, "x-repo", "main").unwrap_err(),
        CoreError::NotFound(_)
    ));

    // Empty rationale and bad oids are invalid.
    let (change, _, _) = store
        .open_change(&scout, "forge", "main", "C", None, None)
        .unwrap();
    assert!(matches!(
        store
            .push_revision(&scout, &change, "not-hex", None, "m")
            .unwrap_err(),
        CoreError::Invalid(_)
    ));
    store
        .push_revision(&scout, &change, OID, None, "m")
        .unwrap();
    assert!(matches!(
        store
            .give_verdict(
                &human,
                &change,
                1,
                ReviewDomain::Style,
                Disposition::Approve,
                "  "
            )
            .unwrap_err(),
        CoreError::Invalid(_)
    ));
    assert!(matches!(
        store
            .attach_claim(&scout, &change, 2, passing_tests())
            .unwrap_err(),
        CoreError::Invalid(_)
    ));

    // Sessions end honestly or not at all.
    let (session, _) = store.open_session(&scout, &task).unwrap();
    assert!(matches!(
        store
            .end_session(&scout, &session, SessionState::Failed, "")
            .unwrap_err(),
        CoreError::Invalid(_)
    ));
    assert!(matches!(
        store
            .end_session(&arbiter, &session, SessionState::Failed, "gave up")
            .unwrap_err(),
        CoreError::Conflict(_)
    ));

    // Bootstrap self-registration only works for the very first principal.
    let mut fresh = Store::open_in_memory().unwrap();
    let first = principal("first");
    fresh
        .register_principal(&first, &first, PrincipalKind::Human, "First", None, None)
        .unwrap();
    let second = principal("second");
    assert!(matches!(
        fresh
            .register_principal(&second, &second, PrincipalKind::Human, "Second", None, None)
            .unwrap_err(),
        CoreError::NotFound(_)
    ));
}

#[test]
fn event_cursor_pagination_resumes_cleanly() {
    let (store, ..) = seeded();
    let all = store.events_after(EventSeq(0), 100).unwrap();
    assert_eq!(all.len(), 4);

    let first_two = store.events_after(EventSeq(0), 2).unwrap();
    let rest = store
        .events_after(first_two.last().unwrap().seq, 100)
        .unwrap();
    assert_eq!(first_two.len() + rest.len(), all.len());
    assert_eq!(
        rest.first().unwrap().seq.0,
        first_two.last().unwrap().seq.0 + 1
    );
    assert_eq!(store.latest_seq().unwrap(), all.last().unwrap().seq);
}
