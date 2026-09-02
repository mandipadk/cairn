//! Search parses what people type, ranks what it finds, and never shows
//! what the searcher could not read.

use cairn_core::{ChangeState, HitKind, SearchQuery};

#[test]
fn a_query_is_words_plus_the_filters_everybody_types() {
    let q = SearchQuery::parse("Carry children repo:cairn state:open by:scout kind:change");
    assert_eq!(q.words, vec!["carry", "children"]);
    assert_eq!(q.repo.as_deref(), Some("cairn"));
    assert_eq!(q.state, Some(ChangeState::Open));
    assert_eq!(q.by.as_deref(), Some("scout"));
    assert_eq!(q.kind, Some(HitKind::Change));

    // A number on its own means one change.
    let q = SearchQuery::parse("#12");
    assert_eq!(q.number, Some(12));
    assert!(q.words.is_empty());

    // An unknown key is just a word with a colon in it; an unknown
    // state is not silently a filter.
    let q = SearchQuery::parse("foo:bar state:sideways");
    assert_eq!(q.words, vec!["foo:bar", "state:sideways"]);
    assert!(q.state.is_none());

    assert!(SearchQuery::parse("   ").is_empty());
    assert!(!SearchQuery::parse("kind:person").is_empty());
}
