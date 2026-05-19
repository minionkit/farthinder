> [!WARNING]
> This project is in its early Proof of Concept days! Expect rapid changes, missing pieces, and untested features.
> We are still sorting out the official project license. For now, all rights and copyright are reserved.

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

- **Pragmatic 80/20 Security**: Implementing a few basic, frictionless protections puts you leagues ahead of the baseline. farthinder avoids heavy static analysis and relies on the broader industry to find exploits. It combines a strict quarantine on bleeding-edge versions with just-in-time vulnerability checks. We simply pause your install long enough for security researchers to find the landmines, verifying against the latest databases right before allowing any code to execute.

- **Transparent Execution**: You don't change how you work. Run pnpm install, uv sync, or cargo build exactly as you always do. farthinder silently intercepts the calls via local shims, protecting your environment and catching rogue background scripts without altering your muscle memory.

- **Zero-Infrastructure Configuration**: No proxies, custom artifact endpoints, or enterprise accounts to set up. It protects your machine globally right out of the box, while respecting standard, layered configuration files for any project-specific overrides.

## See It In Action

```console
$ fart install

Created shims for 5 tools:
  npm, bun, pnpm, yarn, uv

Shim directory: ~/.farthinder/bin
Run `exec $SHELL` or open a new terminal to activate.

$ cd ~/some-project

$ bun update

┏━ Farthinder Active ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  Protecting npm                                               ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

[0.06ms] ".env.local"
bun update v1.3.11 (af24e281)
Checked 689 installs across 866 packages (no changes) [3.62s]

┏━ Farthinder Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  46 packages checked                                          ┃
┃  19 versions quarantined across 10 packages                   ┃
┃    motion (12.39.0)                                           ┃
┃    vitest (5.0.0-beta.3)                                      ┃
┃    nitro-nightly (3.0.1-20260518-130639-31265391, 3.0.1-2026  ┃
┃    @types/react (15.7.37, 16.14.70, 17.0.92, and 2 more)      ┃
┃    posthog-js (1.374.0, 1.374.1, 1.374.2)                     ┃
┃    @tailwindcss/vite (0.0.0-insiders.cea8c97)                 ┃
┃    tailwindcss (0.0.0-insiders.cea8c97)                       ┃
┃    @storybook/react-vite (0.0.0-pr-34833-sha-5b66f0f7)        ┃
┃    storybook (0.0.0-pr-34833-sha-5b66f0f7)                    ┃
┃    @types/node (25.9.0, 25.9.1)                               ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

$ bun run dev
Yay 🎉 Running normally without interference
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
| Network interception (MITM proxy) | ✅ | ✅ | 🔧 |
| Kernel sandbox | ✅ | ✅ | 🔧 |
| Sensitive file read protection | ✅ | ✅ | 🔧 |
| File write restriction | ✅ | ✅ | 🔧 |
| Execution allowlist | 🔧 | 🔧 | 🔧 |
| Privilege escalation blocking | 🔧 | 🔧 | 🔧 |
| Symlink attack prevention | 🔧 | 🔧 | — |
| Clipboard/screen exfiltration blocking | 🔧 | 🔧 | 🔧 |
| seccomp syscall filtering | — | 🔧 | — |

✅ implemented · 🔧 planned
