# EMAIL DETECTOR

A **production-grade email detection binary** written in modern Rust with performance, security, and correctness as first-class goals.

Built with: Rust (stable) + Cargo. This repository uses Cargo for dependency management and building.

---

## ✨ Features

* **RFC-compliant validation** — strict email format checks
* **Thread-safe by default** — safe for concurrent usage (Rust's ownership model + `Send`/`Sync` where appropriate)
* **Performance optimized** — idiomatic zero-cost abstractions, minimal allocations
* **Security hardened** — input size limits and safe parsing to prevent DoS/overflow
* **Panic safe** — graceful handling and `Result`-based APIs
* **Duplicate-free extraction** — collects unique valid emails only (`HashSet` by default)
* **Benchmark & Test Suite** — correctness tests and optional benchmarking

---

## 📌 Use Cases

* Detect and extract email addresses from untrusted input
* Preprocess logs, text, or messages for compliance checks
* Integrate into high-throughput services (log processors, scraping pipelines)

---

## 🚀 Included Components (project layout)

This project is a single-binary Cargo crate. The layout in your repository is:

```
Project/
├─ Cargo.toml
├─ Cargo.lock
├─ .gitignore
├─ README.md
└─ src/
   └─ main.rs      # entry point (fn main)
```

The core detection logic can live in `src/main.rs` for a small utility, or be refactored into modules inside `src/` as the project grows (e.g. `src/detector.rs`).

---

## 🔧 Quick Start (Cargo)

From the project root you can build and run the binary using the following commands.

### Development build

```bash
cargo build
```

### Development run

```bash
cargo run
```

### Release (optimized) build

```bash
cargo build --release
```

### Release run

```bash
cargo run --release
```

> `cargo build --release` enables optimizations and yields an executable in `target/release/`.

---

## 🔌 Dependencies

If your code uses crates such as `num_cpus` or `rayon` for parallelism, add them to `Cargo.toml`. Example:

```toml
[dependencies]
num_cpus = "1.17.0"
```

After editing `Cargo.toml`, run `cargo build` so Cargo will fetch and compile these crates.

---

## ▶️ Running the Program (examples)

### Linux / macOS

```bash
cargo run --release
# or the built executable
./target/release/<your_binary_name>
```

### Windows (PowerShell)

```powershell
cargo run --release
# or the built exe
.	arget
elease\<your_binary_name>.exe
```

### Windows (CMD)

```cmd
cargo run --release
	arget
elease\<your_binary_name>.exe
```

Replace `<your_binary_name>` with the `name` field from your `Cargo.toml` (defaults to the package directory name).

---

## 📊 Expected Output (example)

```
=== RFC 5322 EXACT VALIDATION ===
Full RFC 5322 compliance with quoted strings, IP literals, etc.

✓ Standard format: "user@example.com"
✓ Minimal valid: "a@b.co"
✓ Dot in local part: "test.user@example.com"
✓ Plus sign (Gmail filters): "user+tag@gmail.com"
✓ Exclamation mark: "user!test@example.com"
✓ Hash symbol: "user#tag@example.com"
✓ Dollar sign: "user$admin@example.com"
✓ Percent sign: "user%percent@example.com"
✓ Ampersand: "user&name@example.com"
✓ Apostrophe: "user'quote@example.com"
✓ Asterisk: "user*star@example.com"
✓ Equal sign: "user=equal@example.com"
✓ Question mark: "user?question@example.com"
✓ Caret: "user^caret@example.com"
✓ Underscore: "user_underscore@example.com"
✓ Backtick: "user`backtick@example.com"
✓ Opening brace: "user{brace@example.com"
✓ Pipe: "user|pipe@example.com"
✓ Closing brace: "user}brace@example.com"
✓ Tilde: "user~tilde@example.com"
✓ Simple quoted string: ""user"@example.com"
✓ Quoted string with space: ""user name"@example.com"
✓ Quoted string with @: ""user@internal"@example.com"
✓ Quoted string with dot: ""user.name"@example.com"
✓ Escaped quote in quoted string: ""user\"name"@example.com"
✓ Escaped backslash: ""user\\name"@example.com"
✓ IPv4 literal: "user@[192.168.1.1]"
✓ IPv6 literal: "user@[IPv6:2001:db8::1]"
✓ IPv6 literal: "user@[2001:db8::1]"
✓ Private IPv4: "test@[10.0.0.1]"
✓ IPv6 link-local: "user@[fe80::1]"
✓ IPv6 loopback: "user@[::1]"
✓ IPv6 all zeros: "user@[::]"
✓ IPv6 trailing compression: "user@[2001:db8::]"
✓ IPv4-mapped IPv6: "user@[::ffff:192.0.2.1]"
✓ IPv6 with compression: "user@[2001:db8:85a3::8a2e:370:7334]"
✓ IPv6 full form: "user@[2001:0db8:0000:0000:0000:ff00:0042:8329]"
✓ Subdomain + country TLD: "first.last@sub.domain.co.uk"
✓ Hyphen in domain: "user@domain-name.com"
✓ Numeric domain labels: "user@123.456.789.012"
✓ Single-char TLD: "user@domain.x"
✓ Numeric TLD: "user@domain.123"
✓ Consecutive dots in local: "user..double@domain.com"
✓ Starts with dot: ".user@domain.com"
✓ Ends with dot: "user.@domain.com"
✓ Consecutive dots in domain: "user@domain..com"
✓ Missing local part: "@example.com"
✓ Missing domain: "user@"
✓ Missing @: "userexample.com"
✓ Double @: "user@@example.com"
✓ Missing TLD: "user@domain"
✓ Domain starts with dot: "user@.domain.com"
✓ Domain ends with dot: "user@domain.com."
✓ Domain label starts with hyphen: "user@-domain.com"
✓ Domain label ends with hyphen: "user@domain-.com"
✓ Unquoted space: "user name@example.com"
✓ Space in domain: "user@domain .com"
✓ Unclosed quote: ""unclosed@example.com"
✓ Quote in middle without @: ""user"name@example.com"
✓ Invalid IPv4 (3 octets): "user@[192.168.1]"
✓ Invalid IPv4 (octet > 255): "user@[999.168.1.1]"
✓ Invalid IPv4 (octet = 256): "user@[192.168.1.256]"
✓ Invalid IPv6 (bad hex): "user@[gggg::1]"

Result: 63/63 passed (100%)

======================================================================

=== TEXT SCANNING (Content Detection) ===
Conservative validation for PII detection

✓ Email in sentence
  Input: "Contact us at support@company.com for help"
  Found: support@company.com

✓ Multiple emails
  Input: "Send to: user@example.com, admin@test.org"
  Found: user@example.com admin@test.org

✓ After colon
  Input: "Email: test@domain.co.uk"
  Found: test@domain.co.uk

✓ In angle brackets
  Input: "<user@example.com>"
  Found: user@example.com

✓ In parentheses
  Input: "(contact: admin@site.com)"
  Found: admin@site.com

✓ Apostrophe blocks extraction
  Input: "That's john'semail@example.com works"

✓ % blocks extraction
  Input: "user%test@domain.com"

✓ ! blocks extraction
  Input: "user!name@test.com"

✓ # blocks extraction
  Input: "user#admin@example.com"

✓ IP literal in scan mode
  Input: "Server: user@[192.168.1.1]"

✓ Consecutive dots
  Input: "user..double@domain.com"

✓ No TLD
  Input: "test@domain"

✓ Starts with dot
  Input: ".user@domain.com"

✓ No @ symbol
  Input: "no emails here"

✓ Period after email
  Input: "Contact: user@example.com."
  Found: user@example.com

✓ Exclamation after email
  Input: "Email user@example.com!"
  Found: user@example.com

✓ Question mark after email
  Input: "Really? user@example.com?"
  Found: user@example.com

Result: 17/17 passed (100%)

======================================================================

=== EMAIL DETECTION TEST ===
Testing both exact validation and text scanning

SENSITIVE: "Simple email: user@example.com in text"
  => Found emails: user@example.com

SENSITIVE: "Multiple emails: first@domain.com and second@another.org"
  => Found emails: first@domain.com second@another.org

CLEAN    : "user..double@domain.com"

SENSITIVE: "Complex: john.doe+filter@sub.domain.co.uk mixed with text"
  => Found emails: john.doe+filter@sub.domain.co.uk

CLEAN    : "No emails in this text at all"

SENSITIVE: "Contact us at support@company.com for help"
  => Found emails: support@company.com

SENSITIVE: "Multiple: first@test.com, second@demo.org"
  => Found emails: first@test.com second@demo.org

CLEAN    : "invalid@.com and test@domain"

======================================================================
✓ Email Detection Complete
======================================================================
=== PERFORMANCE BENCHMARK ===
Threads: 16
Iterations per thread: 100000
Total operations: 128000000
Time: 2610 ms
Ops/sec: 49042145
Validations: 80000000

======================================================================
✓ 100% RFC 5322 COMPLIANT
✓ SOLID Principles Applied
✓ Thread-Safe Implementation
✓ Production-Ready Performance
======================================================================

Features:
  • Quoted strings: "user name"@example.com
  • IP literals: user@[192.168.1.1] (exact mode only)
  • All RFC 5322 special characters
  • Alphanumeric TLDs
  • Single-character TLDs
  • Conservative text scanning (strict boundaries)
  • Proper word boundary detection (no false positives)
======================================================================
```

(Actual numbers will vary by machine and implementation.)

---

## 🧪 Testing & Benchmarks

* Run unit and integration tests:

```bash
cargo test
```

* Use Criterion or `cargo bench` for more accurate benchmarks if you add them.

---

## 📋 Requirements

* **Rust toolchain:** stable (use `rustup` to install). Tested on stable Rust (1.70+ recommended).
* **OS:** Linux, macOS, or Windows
* **Hardware:** any modern CPU. Release builds can use CPU features when explicitly enabled.

---

## ⚠️ Important Notes

* If you enable CPU-specific optimizations (via `RUSTFLAGS` or `cargo` settings), the produced binary may not be portable across older CPUs. Prefer portable builds for distribution.

* To auto-detect CPU count in Rust use `num_cpus::get()`; add `num_cpus` to `Cargo.toml` as shown above.

* For Windows PowerShell users: `cargo run --release` works directly. To execute the built binary from PowerShell, prefix with `./` (e.g. `./target/release/<your_binary_name>.exe`).

---

## ✅ Security Features (Rust implementation)

* Input size validation — upper limit (for example, 1 MiB) on text parsed
* No manual memory management — no buffer overflows thanks to Rust
* `Result`-based error handling — no panics for recoverable input errors
* Thread-safe primitives and immutable default sharing patterns

---
