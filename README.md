# personal-twin

AI-agent-safe personal data twin: a local git repo + KeePassXC vault + one CLI (`twin`) that lets coding agents (ZCode / Codex / Claude Code / Copilot) use your credentials **without ever touching the plaintext**.

## The core idea

Plaintext secrets should never enter an AI conversation. `twin` enforces this structurally:

- **consume**: `twin inject <entry> --env VAR -- <cmd>` decrypts from the vault and injects the value **directly into the child process environment** (or stdin). The agent only sees the child's output.
- **intake**: `twin form` (single) or `--mode batch` (multi-entry grid, one submit) serves a one-shot local web page; values go straight from the browser into the vault — the agent only receives per-row status JSON. Duplicate/missing titles are rejected per row.
- **register**: one-shot CLI intake that also updates the account ledger, leak-audit tokens, runs an audit and a backup.
- **audit**: scans your cloud-synced folders for leaked PII tokens (regenerated weekly via scheduled task), allowlist for intentionally-public items.
- **backup**: AES-256 encrypted copy of contacts + vault snapshots + git commit; verified by decrypt roundtrip.
- **autounlock**: optional DPAPI-protected master key (bound to the Windows user + machine) so intake/retrieval need zero human typing. Revoke anytime with `twin autounlock off`.

## Layout (TWIN_HOME, default D:\personal-twin)

```
profile.md      L0 public identity (name, handles, public accounts)
contacts.md     L1 PII (phones, emails, wechat, qq) — never leaves the machine in plaintext
accounts.md     L2 account ledger (metadata only, points at vault entries)
inventory/      L2 asset inventory (servers, SSH fingerprints, MCP/LLM config map, audit tokens)
secrets.kdbx    L3 KeePassXC vault (gitignored)
```

Cloud only ever receives: `contacts.md.enc` (AES-256-CBC/PBKDF2) + `secrets-*.kdbx` snapshots.

## Quickstart

```bash
pip install pykeepass
export TWIN_HOME=D:\personal-twin            # optional override
python twin.py check                          # scaffold check
printf 'your-vault-password' | python twin.py autounlock on --pw-stdin
python twin.py inject "My API" --env KEY -- python -c "import os; print(len(os.environ['KEY']))"
python twin.py form "Intake" --mode batch --group LLM-API \
  --field title=平台名 --field url="Base URL" --field apikey="API Key"
python twin.py audit                          # must exit 0
```

Environment: `TWIN_HOME` (repo root), `TWIN_BACKUP_DEST` (encrypted backup destination), `TWIN_VAULT` (extra dir to leak-audit).

## Wiring it into your agents

Add the four-layer rule to your global `AGENTS.md` (see SKILL.md), drop `SKILL.md` into your skills directory, and put `twin.py` on PATH. From then on every session knows: consume via `inject`, intake via `form`/`register`, never `get`, never write secrets to synced files.

## Security hardening (v1.1)

- `twin list` masks email/phone-shaped usernames before printing (no PII into agent context)
- unlock session file stores the master password **DPAPI-encrypted**, never plaintext
- `inject` chains: `python twin.py inject A --field url --env BASE -- python twin.py inject A --env KEY -- cmd` injects multiple fields into one child process
- every retrieval/intake/approach logs to `audit.log` (titles only, never values)

## Threat model (honest version)

With `autounlock on`, the trust boundary is "any process running as your Windows user" — the same tier as your `~/.ssh` keys. What this system defends against: secrets leaking into AI context / cloud-synced plaintext / weekly-distilled notes, with a full audit trail. What it does not defend against: an adversary already executing as your user. Turn autounlock off to require human unlock per session.

## License

MIT
