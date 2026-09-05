//! Every end-to-end test of the forge, built as one binary.
//!
//! Each file under `tests/` would otherwise become its own executable that
//! links the whole workspace; with thirty of them, the suite spent its time
//! in the linker and almost none of it running tests. One binary links once
//! and runs every test in parallel. Add a new file here with a `mod` line.

mod account_flow;
mod assets_flow;
mod attention_budget_flow;
mod auth_flow;
mod claim_form_flow;
mod common;
mod concurrency_flow;
mod credential_flow;
mod csrf_flow;
mod event_scope_flow;
mod fsck_flow;
mod git_flow;
mod home_flow;
mod hostile_input_flow;
mod import_flow;
mod inbox_flow;
mod invite_flow;
mod lease_flow;
mod limits_flow;
mod mcp;
mod mirror_flow;
mod pages_flow;
mod passkeys_flow;
mod password_flow;
mod public_flow;
mod read_boundary_flow;
mod recovery_flow;
mod repo_lifecycle_flow;
mod reset_flow;
mod search_flow;
mod security_flow;
mod sessions_flow;
mod teams_flow;
mod threads_flow;
mod threads_page_flow;
mod transfer_flow;
mod verify_flow;
mod visibility_flow;
mod web_flow;
mod welcome_flow;
