# Best practices for this repo

## Mindset

**Rust's compiler is your refactoring safety net.** Make a breaking change → fix every compile error → you're back to working code. Leverage this aggressively. Don't over-architect v1; do refactor early and often. A messy compile is better than a clean overdesign.

---

## 1. Enums Over Everything

This is the single biggest habit to build. In TS you'd use string unions; in Python, string constants or dicts. In Rust, **use enums**.

```rust
// ❌ TS/Python brain — loose strings, no exhaustiveness
let status = "active";

// ✅ Rust brain — the compiler now owns your state space
enum Status { Active, Paused, Terminated }
```

Why: `match` forces exhaustive handling. When you add a variant later, every match site breaks at compile time and you're forced to handle it. This is the refactoring superpower — add a variant, follow the compiler errors, done.

Use `#[derive(Debug, Clone, PartialEq)]` liberally on enums.

## 2. Structs Over Tuples Over Primitives

Don't pass around `(String, u32, bool)`. Wrap it in a struct. The cost is near zero; the clarity is enormous.

```rust
// ❌ Positional soup
fn create_user(name: String, age: u32, active: bool) -> ...

// ✅ Named fields, zero-cost abstraction
struct User { name: String, age: u32, active: bool }
```

Same principle: newtype wrappers for domain concepts.

```rust
struct UserId(String);   // can't accidentally pass a ProjectId where UserId expected
```

## 3. Result<>, Not Unwrap

For v1: `.unwrap()` and `.expect("why")` are fine in `main`, tests, and prototype code. But in library/application logic, return `Result<T, E>` up the call stack. Let the caller decide.

**Define your error enum early — even if it's simple:**

```rust
#[derive(Debug)]
enum AppError { Io(std::io::Error), Parse(String), NotFound }
```

Use `thiserror` or `anyhow` (prefer `thiserror` for libraries, `anyhow` for apps). Don't wait — it's 5 lines and saves you from `.unwrap()` debt.

## 4. Ownership: Don't Fight It, Don't Over-Optimize It

The TS/Python instinct is to clone everything to avoid borrow checker pain. For v1, **that's actually fine.** Clone aggressively to get working code. Then profile. Then reduce clones.

```rust
// v1: just clone it, ship it
let name = user.name.clone();

// later: replace with &str or Arc<str> if profiler says so
```

**Anti-patterns to avoid from day 1:**

- **Putting references in structs** to "avoid clones." This pins your struct to a lifetime and makes it infectious. For v1, own your data (`String`, `Vec<T>`). Introduce borrowing only when needed.
- **`Rc<RefCell<T>>`** to make things "work like Python." If you reach for this, stop. Restructure ownership instead. If you truly need shared mutation, `Rc<RefCell<>>` is acceptable for v1, but treat it as a code smell to revisit.

## 5. Traits: Define Late, Implement Early

Don't design trait hierarchies upfront. Write concrete types first. When you see duplication, then extract a trait.

```rust
// v1: just write the function
fn process_csv(data: &str) -> Vec<Record> { ... }

// v2: when you need JSON too, THEN make a trait
trait DataSource { fn fetch_records(&self) -> Vec<Record>; }
```

**Do use standard traits early:** `From`/`Into`, `Display`, `Debug`, `Default`, `Iterator`. These are free API surface.

## 6. Module Structure: Start Flat

```text
src/
  main.rs       // binary entry
  lib.rs        // library root (re-exports)
  models.rs     // one file is fine
  handlers.rs   // split later
```

Don't create `src/models/user.rs`, `src/models/project.rs` on day one. Put `User` and `Project` in `models.rs`. When it exceeds ~300 lines, split. Rust modules are not Python packages — they're cheap to reorganize.

## 7. Common Pitfalls

| TS/Python Habit | Rust Foot-Gun | Fix |
|---|---|---|
| Mutable by default | `let mut` everywhere | Default to immutable; add `mut` only when needed |
| `null` / `undefined` | `Option<T>` — don't unwrap blindly | Pattern match or use `?` operator |
| Exceptions | Panics via unwrap/index | Return `Result`, use `?` to propagate |
| Inheritance / subclassing | No inheritance | Composition + trait impls |
| `class` with methods on everything | Methods on everything | Free functions are idiomatic; use methods when they access `self` |
| `async/await` everywhere | Async is viral and has overhead | Use async only at I/O boundaries; keep logic sync |
| Dynamic typing / `any` | `dyn Trait` everywhere | Use generics (`impl Trait`) first; `dyn` only when you need dynamic dispatch |
| Catch-all match `_ => ()` | Silently ignores new enum variants | Use `_ => ()` only temporarily; aim for exhaustive matches |
| Stringly-typed configs | `HashMap<String, String>` everywhere | Parse into typed structs with `serde` + `clap`/`config` |

## 8. Dependency Discipline

For v1, use these — they're standard and save time:

- **`serde`** — serialization/deserialization. Always.
- **`clap`** — CLI args if needed.
- **`thiserror`** — error types.
- **`tracing`** — structured logging (not `println!`).

Don't add anything else until you need it. Every dependency is a maintenance cost.

## 9. The Refactor Loop

```
Write working code → spot a smell → make the change → fix compile errors → done
```

Specific refactors to do *while iterating*, not "later":

- **String → enum** the moment you see the same literal in two places.
- **Tuple → struct** the moment you can't remember what field is what.
- **Clone → borrow** only when profiling shows it matters.
- **Free function → method** when you keep passing the same `self` arg.
- **`dyn Trait` → generics** when you don't actually need runtime dispatch.
- **Catch-all `_ =>` → explicit arms** before merging to main.

The compiler will catch everything you break. Trust it. Refactor fearlessly.

## 10. Testing: Do the Minimum That Helps

```rust
#[test]
fn it_works() { ... }
```

Don't set up elaborate test frameworks for v1. Use `insta` for snapshot testing — fast iteration on JSON parsing, metadata rewriting, etc. Write tests for core logic, not for wiring. Rust's type system already tests a lot for you.

## 11. Comments: Less Is More

Code comments must be minimal and only explain **why** something non-obvious is done — never **what** the code does. The code itself should be self-documenting. If you need to explain what's happening, refactor first. Too many comments bury the important notes.

```rust
// ❌ Noise — the code already says this
// increment the counter
counter += 1;

// ❌ Noise — step-by-step narration
// first we parse the url, then we extract the host
let url = Url::parse(&raw)?;
let host = url.host_str()?;

// ✅ Helpful — explains a non-obvious constraint
// npm's compact metadata format omits timestamps, force full format
headers.insert("accept", "application/json".parse().unwrap());
```

When in doubt, leave it out. You can always explain something in conversation. You can't easily un-clutter a file.

---

## 0. Build Commands

**Always use `rtk` to run any commands.** Never run `cargo check`, `cargo build`, or any other command directly. The only allowed commands are:

```
rtk cargo check
rtk cargo build
```

---

**TL;DR:** Enums everywhere. Own your data (don't borrow prematurely). Clone first, optimize later. Let the compiler catch your refactors. Ship v1, then clean up — Rust makes cleanup safe.
