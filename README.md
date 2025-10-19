# 🚀 Schnell CLI

> ⚙️ A focused, modern toolchain to tame mobile provisioning across iOS today and Android tomorrow.

`schnell` lives inside this workspace and ships as a single binary that automates the repetitive parts of setting up mobile projects. It currently streamlines Apple App Store Connect workflows for iOS provisioning while laying the groundwork for Android credential automation and Flutter-friendly tooling. Think of it as a Rust-powered reinterpretation of fastlane with batteries included for cross-platform teams.

## 🦀 Built With Rust

- Predictable builds with zero runtime dependencies.
- Strong type-safety and expressive error handling via `thiserror`.
- Fast startup, making it easy to slot into CI or local scripts.

## ⚡️ Getting Started

| Action | Command | Why it matters |
| --- | --- | --- |
| Build | `cargo build -p cli` | Compile the CLI and dependencies in debug mode. |
| Run | `cargo run -p cli -- --help` | Explore available subcommands and flags. |
| Install | `cargo install --path crates/cli` | Drop the binary into your Cargo bin dir for reuse outside the repo. |

All commands operate on `crates/cli`. Builds land under `target/debug/`, and `cargo install` places the binary in your `$CARGO_HOME/bin`.

## 🍎 iOS Provisioning Workflow

After installing the CLI, you can execute a typical App Store Connect provisioning sequence:

```bash
schnell ios login --issuer-id "<ISSUER_ID>" --key-id "<KEY_ID>" --private-key <PATH_TO_P8_PRIVATE_KEY_FILE>

schnell ios ensure-bundle-id --id com.mycompany.myapp --name myapp

schnell ios ensure-certificate --team-id <TEAM_ID> --private-key-pem private.key

schnell ios ensure-provisioning-profile --bundle-id com.mycompany.myapp
```

🔐 `ios login` stores your App Store Connect API credentials securely so future commands authenticate automatically.  
📦 `ios ensure-bundle-id` confirms the bundle identifier exists, creating it when needed.  
🔏 `ios ensure-certificate` creates or reuses a signing certificate for the specified team using your private key. 
> The private key can be omitted, the cli will look for a *.key file in the current folder

📝 `ios ensure-provisioning-profile` keeps a provisioning profile in sync with the bundle identifier and certificates.

Replace placeholders with values from your Apple developer account. Keep sensitive files such as `.p8` keys outside of version control—`crates/sys_tools` provides local storage helpers for that purpose.

## 🗺️ Roadmap

- [ ] Android Play Console automation for service accounts, app packages, and key management.
- [ ] Flutter helper packages and templates that wire up signing assets automatically.
- [ ] Unified provisioning abstractions to make iOS and Android commands feel symmetric.
- [ ] Rich diagnostics and guided setup flows for success on the first run.

Have ideas or requests? Open an issue or drop a note in the backlog—`schnell` is just getting started. 🛠️
