//! The client side of the Cairn protocol: everything that talks to a
//! forge over HTTP without being one. Agents connect through [`mcp`];
//! CI re-runs claims through [`verify`]. Licensed Apache-2.0 so that any
//! tool can embed it; the forge these talk to is AGPL-3.0.

pub mod mcp;
pub mod verify;
