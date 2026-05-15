# Farthinder

**Dev safely. Slow down before you bump your dependencies.**

> **farthinder** `/²fɑːrtˌhɪndɛr/ noun SE-SV`
> 
> Swedish for "speed bump", a physical obstacle designed to force a temporary slowdown, ensuring safety before proceeding forward.

![Cover](./docs/cover.jpg)

## Supply-Chain Attacks

Modern software relies on an incredible open-source ecosystem. But that reliance is being actively weaponized. Supply chain attacks are spreading faster than ever, and while the security community is remarkably quick to flag exploits, the danger lies in bad timing. If you happen to run npm install during those brief minutes a compromised package is live in the wild, your machine is infected.

You already know this is a risk. But the existing solutions do not fit how developers actually work. Enterprise registries are heavy, expensive, and entirely impractical for your growing list of side-projects. Native package manager mitigations are fragmented and easily bypassed if a background script calls the wrong binary. You need reliable, universal protection that does not require an infrastructure team to set up.

**Farthinder** (`fart`) is a lightweight CLI that uses shims to intercept your package managers, automatically quarantining new versions and verifying them against the latest vulnerability databases. It provides a local layer of endpoint security by forcing your workflow to slow down just enough to keep you safe.

- **Pragmatic 80/20 Security**: Implementing a few basic, frictionless protections puts you leagues ahead of the baseline. speed-bump avoids heavy static analysis and relies on the broader industry to find exploits. It combines a strict quarantine on bleeding-edge versions with just-in-time vulnerability checks. We simply pause your install long enough for security researchers to find the landmines, verifying against the latest databases right before allowing any code to execute.

- **Transparent Execution**: You don't change how you work. Run pnpm install, uv sync, or cargo build exactly as you always do. speed-bump silently intercepts the calls via local shims, protecting your environment and catching rogue background scripts without altering your muscle memory.

- **Zero-Infrastructure Configuration**: No proxies, custom artifact endpoints, or enterprise accounts to set up. It protects your machine globally right out of the box, while respecting standard, layered configuration files for any project-specific overrides.

## See It In Action

```console
$ fart --install 
- created shims for 6 supported tools:
    npm, bun, uv, python, pip
- installed CA root certificate
- pre-fetching vulnerability databases...
- DONE

$ cd ~/some-project

$ bun install
╭─ Farthinder ────────────────────────────────────────────╮
│ Watching npm traffic                                     │
╰─────────────────────────────────────────────────────────╯

bun install v1.3.11 (af24e281)
 + typescript@6.0.3
 1 package installed [1027.00ms]

╭─ Farthinder Summary ───────────────────────────────────╮
│ 8 packages checked                                       │
│ 2 versions quarantined across 2 packages                 │
│   lodash (4.18.1), typescript (6.0.4)                   │
╰─────────────────────────────────────────────────────────╯
```

## Safety nets

### By ecosystem

| | JS | Python | Rust | Elixir | Java |
|---|---|---|---|---|---|
| Time-delay quarantine (48h) | ✅ | ✅ | 🔧 | 🔧 | 🔧 |
| Vulnerability database checks | 🔧 | 🔧 | 🔧 | 🔧 | 🔧 |
| Block exotic transitive sources | 🔧 | 🔧 | 🔧 | 🔧 | 🔧 |
| Block postinstall scripts | 🔧 | — | — | — | — |
| Trust policy (no-downgrade) | 🔧 | 🔧 | 🔧 | 🔧 | 🔧 |

### By platform

| | macOS | Linux | Windows |
|---|---|---|---|
| Network interception (MITM proxy) | ✅ | 🔧 | 🔧 |
| Kernel sandbox | 🔧 | 🔧 | 🔧 |
| Sensitive file read protection | 🔧 | 🔧 | 🔧 |
| File write restriction | 🔧 | 🔧 | 🔧 |
| Execution allowlist | 🔧 | 🔧 | 🔧 |
| Privilege escalation blocking | 🔧 | 🔧 | 🔧 |
| Symlink attack prevention | 🔧 | 🔧 | — |
| Clipboard/screen exfiltration blocking | 🔧 | 🔧 | 🔧 |
| seccomp syscall filtering | — | 🔧 | — |

✅ implemented · 🔧 planned
