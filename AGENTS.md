# AGENTS.md
## Build / Test / Lint
- `cargo build` — build project
- `cargo run` — run main binary
- `cargo test` — run full test suite
- `cargo test <test_name>` — run single test
- `cargo check` — fast compile check
- `cargo clippy` — lint
## Code Style
- Imports: std, then external crates, then local; use `use crate::` for local paths
- Formatting: `rustfmt` defaults (4-space indent, snake_case), max 100 cols
- Types/Naming: snake_case for fns/vars/modules; PascalCase for structs/enums/traits; prefer descriptive names
- Error handling: use `thiserror` with `#[error]`; project `Result<T>` = `std::result::Result<T, IpouError>`; propagate with `?`
- Prefer small, focused modules; keep functions short and single-purpose
- Avoid unwrap/expect outside tests; handle errors explicitly
- Tests: place in `tests/` or `mod tests {}`; prefer table-driven where sensible
- Logging: keep messages concise; avoid sensitive data
- Dependencies: add only when necessary; keep versions minimal
- No cursor/copilot rules present
- Keep comments meaningful; avoid dead/commented-out code
- Follow repository conventions; match nearby style for new code