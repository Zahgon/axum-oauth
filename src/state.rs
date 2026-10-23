use crate::oauth::{database::Database, state::State as AuthState};

#[derive(Clone)]
pub struct AppState {
    pub state: AuthState,
    pub database: Database,
}
