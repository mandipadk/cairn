//! The full protocol walk: intent → attempt → output → verification →
//! judgment → policy-decided outcome, all against an in-memory store.

use cairn_core::{
    Capability, ChangeSpec, ClaimKind, ClaimSpec, CoreError, Disposition, Event, EventSeq,
    ObjectFormat, PrincipalId, PrincipalKind, ReviewDomain, SessionState, Store, TaskState,
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
    store
        .create_repo(&human, "forge", "main", ObjectFormat::Sha1)
        .unwrap();
    // Agents act only under grants; the human delegates.
    store
        .issue_grant(
            &human,
            &scout,
            None,
            vec![Capability::Task, Capability::Push, Capability::Review],
            None,
        )
        .unwrap();
    store
        .issue_grant(
            &human,
            &arbiter,
            None,
            vec![Capability::Task, Capability::Review],
            None,
        )
        .unwrap();
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
            ChangeSpec {
                task: Some(task.clone()),
                ..ChangeSpec::new("forge", "main", "Harden slug validation")
            },
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
    // Capability precedes policy: scout holds no merge capability at
    // all, while the human clears capability and hits the policy wall.
    let err = store.merge_change(&scout, &change).unwrap_err();
    assert!(matches!(err, CoreError::Forbidden(_)));
    let err = store.merge_change(&human, &change).unwrap_err();
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
            "grant_issued",
            "grant_issued",
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
    store
        .issue_grant(&human, &sentinel, None, vec![Capability::Review], None)
        .unwrap();

    let (change, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Refactor"))
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
        .open_change(&scout, ChangeSpec::new("forge", "main", "Risky"))
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
        .open_change(&human, ChangeSpec::new("forge", "main", "Self-serve"))
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
        store
            .create_repo(&ghost, "x-repo", "main", ObjectFormat::Sha1)
            .unwrap_err(),
        CoreError::NotFound(_)
    ));

    // Empty rationale and bad oids are invalid.
    let (change, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "C"))
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
    assert_eq!(all.len(), 6);

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

#[test]
fn tokens_authenticate_and_revoke_immediately() {
    let (mut store, human, scout, _) = seeded();

    // Self-mint; the secret resolves to its owner exactly while live.
    let (token, secret, _) = store.mint_token(&scout, &scout, Some("laptop")).unwrap();
    assert!(secret.starts_with("cairn_"));
    assert_eq!(
        store.principal_for_token(&secret).unwrap(),
        Some(scout.clone())
    );
    assert_eq!(store.principal_for_token("cairn_wrong").unwrap(), None);

    // An agent may not mint for someone else; a human may.
    assert!(matches!(
        store.mint_token(&scout, &human, None).unwrap_err(),
        CoreError::Forbidden(_)
    ));
    let (_, human_secret, _) = store.mint_token(&human, &scout, Some("issued")).unwrap();
    assert_eq!(
        store.principal_for_token(&human_secret).unwrap(),
        Some(scout.clone())
    );

    // Revocation is immediate; the metadata never leaks the secret.
    store.revoke_token(&scout, &token).unwrap();
    assert_eq!(store.principal_for_token(&secret).unwrap(), None);
    let tokens = store.tokens_of(&scout).unwrap();
    assert_eq!(tokens.len(), 2);
    assert!(tokens.iter().any(|t| t.revoked));
    assert!(!serde_json::to_string(&tokens).unwrap().contains("cairn_"));
}

#[test]
fn capability_law_scopes_expires_and_revokes() {
    let mut store = Store::open_in_memory().unwrap();
    let human = PrincipalId::new("ada").unwrap();
    let agent = PrincipalId::new("drone").unwrap();
    store
        .register_principal(&human, &human, PrincipalKind::Human, "Ada", None, None)
        .unwrap();
    store
        .register_principal(
            &human,
            &agent,
            PrincipalKind::Agent,
            "Drone",
            Some("m"),
            None,
        )
        .unwrap();
    store
        .create_repo(&human, "alpha", "main", ObjectFormat::Sha1)
        .unwrap();
    store
        .create_repo(&human, "beta", "main", ObjectFormat::Sha1)
        .unwrap();

    // No grant: refused, and the refusal says what to do about it.
    let err = store
        .open_change(&agent, ChangeSpec::new("alpha", "main", "X"))
        .unwrap_err();
    match err {
        CoreError::Forbidden(message) => {
            assert!(
                message.contains("push"),
                "should name the capability: {message}"
            );
            assert!(
                message.contains("/api/grants"),
                "should say how to fix: {message}"
            );
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }

    // Repo-scoped grant covers alpha, not beta, and not repo-less work.
    let (grant, _) = store
        .issue_grant(&human, &agent, Some("alpha"), vec![Capability::Push], None)
        .unwrap();
    store
        .open_change(&agent, ChangeSpec::new("alpha", "main", "X"))
        .unwrap();
    assert!(matches!(
        store
            .open_change(&agent, ChangeSpec::new("beta", "main", "Y"))
            .unwrap_err(),
        CoreError::Forbidden(_)
    ));
    // Capability is not identity: push does not confer review.
    let (change, _, _) = store
        .open_change(&agent, ChangeSpec::new("alpha", "main", "Z"))
        .unwrap();
    store
        .push_revision(&agent, &change, OID, None, "z")
        .unwrap();
    assert!(matches!(
        store
            .give_verdict(
                &agent,
                &change,
                1,
                ReviewDomain::Correctness,
                Disposition::Approve,
                "self-review"
            )
            .unwrap_err(),
        CoreError::Forbidden(_)
    ));

    // Revocation is immediate.
    store.revoke_grant(&human, &grant, "trial over").unwrap();
    assert!(matches!(
        store
            .open_change(&agent, ChangeSpec::new("alpha", "main", "W"))
            .unwrap_err(),
        CoreError::Forbidden(_)
    ));

    // Expired grants do not cover; unexpired ones do.
    store
        .issue_grant(
            &human,
            &agent,
            Some("alpha"),
            vec![Capability::Push],
            Some("2020-01-01T00:00:00Z"),
        )
        .unwrap();
    assert!(matches!(
        store
            .open_change(&agent, ChangeSpec::new("alpha", "main", "W"))
            .unwrap_err(),
        CoreError::Forbidden(_)
    ));
    store
        .issue_grant(
            &human,
            &agent,
            Some("alpha"),
            vec![Capability::Push],
            Some("2100-01-01T00:00:00Z"),
        )
        .unwrap();
    store
        .open_change(&agent, ChangeSpec::new("alpha", "main", "W"))
        .unwrap();

    // Delegation is a human act; agents cannot widen authority.
    assert!(matches!(
        store
            .issue_grant(&agent, &agent, None, vec![Capability::Admin], None)
            .unwrap_err(),
        CoreError::Forbidden(_)
    ));
}

#[test]
fn merge_queue_lifecycle_and_guards() {
    let (mut store, human, scout, _) = seeded();
    let (change, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Queued work"))
        .unwrap();
    store
        .push_revision(&scout, &change, OID, None, "work")
        .unwrap();
    store
        .attach_claim(&scout, &change, 1, passing_tests())
        .unwrap();

    // The queue lands ready work; unready work is refused with policy.
    assert!(matches!(
        store.enqueue_change(&human, &change).unwrap_err(),
        CoreError::PolicyUnsatisfied(_)
    ));
    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();

    // Entering the queue is merge intent: scout holds no merge capability.
    assert!(matches!(
        store.enqueue_change(&scout, &change).unwrap_err(),
        CoreError::Forbidden(_)
    ));
    store.enqueue_change(&human, &change).unwrap();
    assert!(store.queue_entry(&change).unwrap().is_some());
    assert_eq!(store.queue_for("forge", "main").unwrap().len(), 1);
    assert!(matches!(
        store.enqueue_change(&human, &change).unwrap_err(),
        CoreError::Conflict(_)
    ));

    // Merging (here: as the queue would, with a rebased oid) records
    // merged_as and clears the queue.
    let landed = "f".repeat(40);
    let merged = store
        .merge_change_as(&human, &change, Some(&landed))
        .unwrap();
    match &merged.event {
        Event::ChangeMerged { merged_as, .. } => {
            assert_eq!(merged_as.as_deref(), Some(landed.as_str()));
        }
        other => panic!("expected ChangeMerged, got {other:?}"),
    }
    assert!(store.queue_entry(&change).unwrap().is_none());

    // Stacks land bottom-up: a child cannot queue past its open parent.
    let (parent, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Parent"))
        .unwrap();
    store
        .push_revision(&scout, &parent, OID, None, "p")
        .unwrap();
    let (child, _, _) = store
        .open_change(
            &scout,
            ChangeSpec {
                parent_change: Some(parent.clone()),
                ..ChangeSpec::new("forge", "main", "Child")
            },
        )
        .unwrap();
    store.push_revision(&scout, &child, OID, None, "c").unwrap();
    store
        .attach_claim(&scout, &child, 1, passing_tests())
        .unwrap();
    store
        .give_verdict(
            &human,
            &child,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();
    let err = store.enqueue_change(&human, &child).unwrap_err();
    assert!(matches!(err, CoreError::Conflict(_)));
    assert!(err.to_string().contains("bottom-up"), "got: {err}");

    // The owner can withdraw their own queued change.
    store
        .attach_claim(&scout, &parent, 1, passing_tests())
        .unwrap();
    store
        .give_verdict(
            &human,
            &parent,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();
    store.enqueue_change(&human, &parent).unwrap();
    store
        .dequeue_change(&scout, &parent, "want to amend first")
        .unwrap();
    assert!(store.queue_entry(&parent).unwrap().is_none());
}

#[test]
fn provenance_follows_a_landed_commit_to_its_judgment() {
    let (mut store, human, scout, _) = seeded();
    let (change, number, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Touch the parser"))
        .unwrap();
    store
        .push_revision(&scout, &change, OID, None, "parse")
        .unwrap();
    store
        .attach_claim(
            &scout,
            &change,
            1,
            ClaimSpec {
                kind: ClaimKind::Test,
                command: Some("cargo test -p parser".into()),
                passed: true,
                summary: "18 tests passed".into(),
                unchecked: vec!["inputs larger than 1 MiB".into(), "invalid utf-8".into()],
            },
        )
        .unwrap();
    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();

    // Nothing is attributable until the change actually lands.
    assert!(store.provenance_of("forge", OID).unwrap().is_none());

    // The queue rebased it, so the landed commit is not the revision.
    let landed = "b".repeat(40);
    store
        .merge_change_as(&human, &change, Some(&landed))
        .unwrap();

    let found = store
        .provenance_of("forge", &landed)
        .unwrap()
        .expect("attributable");
    assert_eq!(found.change.number, number);
    assert!(
        found.executed_check(),
        "a passing test claim is an executed check"
    );
    assert_eq!(
        found.unchecked(),
        ["inputs larger than 1 MiB", "invalid utf-8"]
    );
    assert_eq!(found.approvals().len(), 1);
    // The reviewed revision's oid is not what the branch carries.
    assert!(store.provenance_of("forge", OID).unwrap().is_none());
    // Another repo's commits are not ours to attribute.
    assert!(store.provenance_of("other", &landed).unwrap().is_none());
}

#[test]
fn reasoning_only_claims_are_not_an_executed_check() {
    let (mut store, human, scout, _) = seeded();
    let (change, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Argued, not run"))
        .unwrap();
    store
        .push_revision(&scout, &change, OID, None, "argue")
        .unwrap();
    store
        .attach_claim(
            &scout,
            &change,
            1,
            ClaimSpec {
                kind: ClaimKind::Reasoning,
                command: None,
                passed: true,
                summary: "the change is obviously safe".into(),
                unchecked: vec!["everything an execution would have covered".into()],
            },
        )
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
    // Default policy will not land argument alone, so force the record
    // the way a repo with a laxer policy would.
    let landed = "c".repeat(40);
    assert!(
        store
            .merge_change_as(&human, &change, Some(&landed))
            .is_err()
    );

    // The distinction the register depends on holds regardless.
    let claims = store.claims_on(&change, 1).unwrap();
    assert!(claims.iter().all(|c| c.kind == ClaimKind::Reasoning));
}

#[test]
fn a_disputed_claim_blocks_the_merge() {
    let (mut store, human, scout, arbiter) = seeded();
    // Runners need the verify capability, like any other authority.
    store
        .issue_grant(&human, &arbiter, None, vec![Capability::Verify], None)
        .unwrap();

    let (change, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Claims something"))
        .unwrap();
    store
        .push_revision(&scout, &change, OID, None, "work")
        .unwrap();
    let (claim, _) = store
        .attach_claim(
            &scout,
            &change,
            1,
            ClaimSpec {
                kind: ClaimKind::Test,
                command: Some("cargo test".into()),
                passed: true,
                summary: "all green".into(),
                unchecked: vec![],
            },
        )
        .unwrap();
    store
        .give_verdict(
            &human,
            &change,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();
    assert!(store.merge_readiness(&change).unwrap().satisfied);

    // Capability first: without it, nobody re-runs anything.
    let bystander = principal("bystander");
    store
        .register_principal(
            &human,
            &bystander,
            PrincipalKind::Agent,
            "By",
            Some("m"),
            None,
        )
        .unwrap();
    assert!(matches!(
        store
            .verify_claim(&bystander, &claim, true, "cargo test", "green")
            .unwrap_err(),
        CoreError::Forbidden(_)
    ));
    // Then independence: a claim cannot vouch for itself, even once its
    // author holds the capability.
    store
        .issue_grant(&human, &scout, None, vec![Capability::Verify], None)
        .unwrap();
    assert!(matches!(
        store
            .verify_claim(&scout, &claim, true, "cargo test", "green here too")
            .unwrap_err(),
        CoreError::Conflict(_)
    ));

    // A runner that could not reproduce it blocks the landing, and the
    // policy trace names who disputed what.
    store
        .verify_claim(
            &arbiter,
            &claim,
            false,
            "cargo test",
            "2 tests failed on a clean tree",
        )
        .unwrap();
    let trace = store.merge_readiness(&change).unwrap();
    assert!(!trace.satisfied);
    let disputed = trace
        .requirements
        .iter()
        .find(|r| r.description.contains("disputed"))
        .expect("the disputed-claim requirement should exist");
    assert!(!disputed.satisfied);
    assert!(disputed.evidence.contains("arbiter"));
    assert!(matches!(
        store.merge_change(&human, &change).unwrap_err(),
        CoreError::PolicyUnsatisfied(_)
    ));

    // Agreement is recorded the same way and leaves the gate open.
    let (fresh, _, _) = store
        .open_change(&scout, ChangeSpec::new("forge", "main", "Reproducible"))
        .unwrap();
    store
        .push_revision(&scout, &fresh, OID, None, "work")
        .unwrap();
    let (good_claim, _) = store
        .attach_claim(
            &scout,
            &fresh,
            1,
            ClaimSpec {
                kind: ClaimKind::Test,
                command: Some("cargo test".into()),
                passed: true,
                summary: "all green".into(),
                unchecked: vec![],
            },
        )
        .unwrap();
    store
        .give_verdict(
            &human,
            &fresh,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();
    store
        .verify_claim(
            &arbiter,
            &good_claim,
            true,
            "cargo test",
            "reproduced: all green",
        )
        .unwrap();
    let trace = store.merge_readiness(&fresh).unwrap();
    assert!(trace.satisfied);
    assert!(
        trace
            .requirements
            .iter()
            .any(|r| r.evidence.contains("reproduced")),
        "the trace should show the re-run"
    );
    let verifications = store.verifications_on(&fresh, 1).unwrap();
    assert_eq!(verifications.len(), 1);
    assert!(verifications[0].agrees);
    assert_eq!(verifications[0].by, arbiter);
}

/// A helper that opens a change with one revision and a claim.
fn change_with_claim(
    store: &mut Store,
    owner: &PrincipalId,
    title: &str,
    spec: ClaimSpec,
) -> cairn_core::ChangeId {
    let (change, _, _) = store
        .open_change(owner, ChangeSpec::new("forge", "main", title))
        .unwrap();
    store
        .push_revision(owner, &change, OID, None, "work")
        .unwrap();
    store.attach_claim(owner, &change, 1, spec).unwrap();
    change
}

fn passing_with_command() -> ClaimSpec {
    ClaimSpec {
        kind: ClaimKind::Test,
        command: Some("cargo test".into()),
        passed: true,
        summary: "green".into(),
        unchecked: vec![],
    }
}

#[test]
fn attention_ranks_by_what_judgment_is_worth() {
    let (mut store, human, scout, arbiter) = seeded();
    store
        .issue_grant(&human, &arbiter, None, vec![Capability::Verify], None)
        .unwrap();

    // Quietly fine: verified, approved, nothing to say about it.
    let settled = change_with_claim(&mut store, &scout, "Settled", passing_with_command());
    let settled_claim = store.claims_on(&settled, 1).unwrap()[0].id.clone();
    store
        .verify_claim(&arbiter, &settled_claim, true, "cargo test", "green")
        .unwrap();
    store
        .give_verdict(
            &human,
            &settled,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "ok",
        )
        .unwrap();

    // Reasoning only.
    let argued = change_with_claim(
        &mut store,
        &scout,
        "Argued",
        ClaimSpec {
            kind: ClaimKind::Reasoning,
            command: None,
            passed: true,
            summary: "obviously safe".into(),
            unchecked: vec!["everything an execution would cover".into()],
        },
    );

    // Reviewers disagree — the heaviest signal there is.
    let contested = change_with_claim(&mut store, &scout, "Contested", passing_with_command());
    store
        .give_verdict(
            &arbiter,
            &contested,
            1,
            ReviewDomain::Correctness,
            Disposition::Approve,
            "fine",
        )
        .unwrap();
    store
        .give_verdict(
            &human,
            &contested,
            1,
            ReviewDomain::Security,
            Disposition::Block,
            "unsafe",
        )
        .unwrap();

    // A runner could not reproduce the claim.
    let disputed = change_with_claim(&mut store, &scout, "Disputed", passing_with_command());
    let disputed_claim = store.claims_on(&disputed, 1).unwrap()[0].id.clone();
    store
        .verify_claim(&arbiter, &disputed_claim, false, "cargo test", "2 failures")
        .unwrap();

    let ranked = store.attention_for("forge").unwrap();
    let order: Vec<&str> = ranked.iter().map(|i| i.change.title.as_str()).collect();
    assert_eq!(
        order[0], "Contested",
        "disagreement outranks everything: {order:?}"
    );
    assert_eq!(
        order[1], "Disputed",
        "a disputed claim comes next: {order:?}"
    );
    assert!(
        !order.contains(&"Settled"),
        "a verified, approved change should not ask for attention: {order:?}"
    );
    assert!(order.contains(&"Argued"));

    // Every ranked item explains itself in a person's words, with
    // evidence in graph terms behind it.
    let top = &ranked[0];
    assert!(top.headline().contains("disagree"));
    assert!(top.score >= cairn_core::SignalKind::ReviewersDisagree.weight());
    let signal = &top.signals[0];
    assert_eq!(signal.kind, cairn_core::SignalKind::ReviewersDisagree);
    assert!(signal.evidence.contains("arbiter"));
    assert!(signal.evidence.contains("block"));

    // The reasoning-only change names both of its problems.
    let argued_item = ranked
        .iter()
        .find(|i| i.change.id == argued)
        .expect("argued change should be ranked");
    let kinds: Vec<_> = argued_item.signals.iter().map(|s| s.kind).collect();
    assert!(kinds.contains(&cairn_core::SignalKind::NoExecutedCheck));
    assert!(kinds.contains(&cairn_core::SignalKind::DeclaredGap));
}

#[test]
fn sampling_draws_agent_only_work_deterministically() {
    let (mut store, human, scout, arbiter) = seeded();

    // Enough agent-judged changes to see the sampling rate bite.
    let mut drawn = 0;
    let mut total = 0;
    for index in 0..60 {
        let change = change_with_claim(
            &mut store,
            &scout,
            &format!("Routine {index}"),
            passing_with_command(),
        );
        store
            .give_verdict(
                &arbiter,
                &change,
                1,
                ReviewDomain::Correctness,
                Disposition::Approve,
                "ok",
            )
            .unwrap();
        total += 1;
        let ranked = store.attention_for("forge").unwrap();
        let item = ranked.iter().find(|i| i.change.id == change);
        if item.is_some_and(|i| {
            i.signals
                .iter()
                .any(|s| s.kind == cairn_core::SignalKind::SpotCheck)
        }) {
            drawn += 1;
        }
    }
    assert!(
        (1..=total / 3).contains(&drawn),
        "sampling should draw a minority of {total} changes, drew {drawn}"
    );

    // The draw is a property of the change, not of when you asked.
    let first = store.attention_for("forge").unwrap();
    let second = store.attention_for("forge").unwrap();
    let ids = |items: &[cairn_core::AttentionItem]| -> Vec<String> {
        items
            .iter()
            .filter(|i| {
                i.signals
                    .iter()
                    .any(|s| s.kind == cairn_core::SignalKind::SpotCheck)
            })
            .map(|i| i.change.id.as_str().to_owned())
            .collect()
    };
    assert_eq!(ids(&first), ids(&second), "sampling must be reproducible");

    // A human judgment retires the sample: it has had its look.
    if let Some(sampled) = first.iter().find(|i| {
        i.signals
            .iter()
            .any(|s| s.kind == cairn_core::SignalKind::SpotCheck)
    }) {
        store
            .give_verdict(
                &human,
                &sampled.change.id,
                1,
                ReviewDomain::Design,
                Disposition::Approve,
                "looked",
            )
            .unwrap();
        let after = store.attention_for("forge").unwrap();
        assert!(
            !after.iter().any(|i| i.change.id == sampled.change.id
                && i.signals
                    .iter()
                    .any(|s| s.kind == cairn_core::SignalKind::SpotCheck)),
            "a change a human judged should stop being sampled"
        );
    }
}
