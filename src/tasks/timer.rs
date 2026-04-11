use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

use crate::net::router::Router;

use super::Dispatcher;

pub async fn run(router: Arc<Mutex<Router>>, dispatcher: Dispatcher) -> crate::Result<()> {
    let mut ticker = interval(Duration::from_secs(1));

    loop {
        ticker.tick().await;
        let actions = router.lock().await.tick(now_ms())?;
        dispatcher.dispatch(actions)?;
    }
}

#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
