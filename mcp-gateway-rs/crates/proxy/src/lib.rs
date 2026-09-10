//! corex-proxy: upstream HTTP/stdio clients, circuit breaker, catalog, health.

pub mod catalog;
pub mod circuit_breaker;
pub mod health;
pub mod stdio;
pub mod upstream;

pub use catalog::{CatalogStore, CatalogWorker};
pub use circuit_breaker::CircuitBreaker;
pub use health::{HealthChecker, HealthStatus};
pub use stdio::ProcessManager;
pub use upstream::{Catalog, UpstreamClient, UpstreamResponse};
