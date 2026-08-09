use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0} not found")]
    NotFound(String),

    /// The command is well-formed but the graph's current state forbids it
    /// (e.g. claiming an already-claimed task). Distinct from `Invalid` so
    /// API layers can map it to 409 rather than 400.
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid: {0}")]
    Invalid(String),

    #[error("merge policy not satisfied: {0}")]
    PolicyUnsatisfied(String),

    /// The actor is authenticated but lacks the capability. The message
    /// names the missing capability and how to obtain it, so an agent
    /// can act on the refusal.
    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error(transparent)]
    Db(#[from] rusqlite::Error),

    #[error("corrupt store at {at}: {reason}")]
    Corrupt { at: String, reason: String },
}
