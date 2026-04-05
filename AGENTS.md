# AGENTS.md

## Build/Test Commands
- `cargo build` - Build the project
- `cargo run` - Run the main binary
- `cargo test` - Run all tests
- `cargo test <test_name>` - Run a specific test
- `cargo check` - Fast compile check without building
- `cargo clippy` - Run linter

## Code Style Guidelines

### Imports
- Group imports: std first, external crates, then local modules
- Use `use crate::` for local imports from lib root

### Formatting
- Use `rustfmt` defaults (4-space indentation, snake_case)
- Max line length: 100 characters (rustfmt default)

### Types & Naming
- Use `snake_case` for functions, variables, modules
- Use `PascalCase` for structs, enums, traits
- Use descriptive names for variables and functions

### Error Handling
- Use `thiserror` for custom error types with `#[error]` attribute
- Define project `Result<T>` type alias for `std::result::Result<T, IpouError>`
- Use `?` operator for error propagation


- sans-io migration plan @./sans-io-migration.md
