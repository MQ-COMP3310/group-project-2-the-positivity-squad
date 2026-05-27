# COMP3310 Assignment 2 — Status

Last updated: **2026-05-14**
Due: **Friday 2026-06-05, 11:55pm (Week 13)**
Spec: `C:\Users\User\Documents\Comp3310 Secure Applications Development\Assignment 2\GroupProjectSpecificationv1.0.pdf`
Repo snapshot used in Task 3: commit `34742cc` on branch `main`

---

## Progress by Part

### Part 1 — Security Analysis (50 marks)

| Task | Marks | Status | Notes |
|---|---|---|---|
| Task 1 — Security requirements (≥5, CIA + OWASP) | 10 | **TODO** | Use OWASP Top 10:**2025** (same as Task 3) |
| Task 2 — Threat model: DFD + trust boundaries + ≥5 STRIDE threats | 15 | **TODO** | Need to draw a DFD (web browser → Flask app → SQLite → file system) |
| Task 3 — Code analysis (a–e) | 20 | **DONE** | 22 findings (V1–V22), 7 figures, references in APA 7 |
| Task 4 — Summary and recommendations | 5 | **TODO** | One-paragraph wrap-up, do this last in Part 1 |

### Part 2 — Authentication (30 marks)

| Task | Marks | Status |
|---|---|---|
| Task 5 — Security requirements + design (non-logged-in / logged-in / admin) | 15 | TODO |
| Task 6 — Update threat model with new auth feature | 5 | TODO |
| Task 7 — Implementation + security tests | 10 | TODO |

Flask-Login is already in `requirements.txt` so we don't need a new dependency.

### Part 3 — Two extra features (40 marks)

Group has not picked the two features yet. Each feature gets:
- Task 8 — Design + threat model (10 marks)
- Task 9 — Implementation + tests (10 marks)

### Part 4 — Group process (30 marks, individual)

| Task | Marks | Status |
|---|---|---|
| Task 10 — Team values statement (from Week 9 workshop) | 5 | TODO |
| Task 11 — Weekly project log (Weeks 9–13, table) | 10 | TODO |
| Task 12 — Peer review (each member reviews ≥2 items) | 10 | TODO |
| Task 13 — Individual reflection (per member) | 5 | TODO |

### Recorded presentation (10 marks, separate from report)

10 minutes, all members speak. Covers: security analysis, design decisions, features, testing, individual contributions. Recording not yet done.

---

## Tools used (Task 3 evidence)

All outputs are in `security-evidence/`:

| Tool | Version | Result |
|---|---|---|
| `pip-audit` | 2.10.0 | 1 CVE — CVE-2026-27205 on flask 3.0.3 |
| `safety` | 3.7.0 | **Failed** — broken by `click` downgrade from `semgrep` install (documented as V22) |
| `bandit` | 1.9.4 | 2 Medium B608 findings (SQL injection) |
| `semgrep` | 1.163.0 | 4 blocking findings (SQL injection) |
| `gitleaks` | 8.x | No leaks (provider-pattern only; doesn't catch generic SECRET_KEY) |
| GitHub CodeQL | default Python pack | 5 alerts (4 High + 1 Medium) |
| GitHub Dependabot | — | 1 alert (CVE-2026-27205, Low) |

---

## Headline findings (full list V1–V22 in Task 3 report)

| Class | Findings |
|---|---|
| Injection (A05:2025) | SQL injection at `main.py:71` and `:75` (V1); stored XSS via SVG uploads (V11) |
| Broken Access Control (A01:2025) | No auth on any route (V5); CSRF on all forms (V6, V7); path traversal in upload filename (V9); arbitrary file delete (V13); open redirect at `main.py:35` (V21) |
| Authentication (A07:2025) | No auth model at all (V5) |
| Cryptographic Failures (A04:2025) | Hard-coded `SECRET_KEY` (V2); missing cookie flags (V15) |
| Security Misconfiguration (A02:2025) | `debug=True` (V3); binds 0.0.0.0 (V4); missing security headers (V15) |
| Insecure Design (A06:2025) | Unrestricted file upload (V8); no `MAX_CONTENT_LENGTH` (V10); silent file overwrite (V12); no input validation (V16) |
| Software Supply Chain (A03:2025) | flask 3.0.3 has CVE-2026-27205 (V18); no lock file / pip resolver downgrades broke safety (V22) |
| Data Integrity (A08:2025) | No file hashing, no `--require-hashes` (V20) |
| Logging (A09:2025) | No audit logging anywhere (V19) |
| Exception Handling (A10:2025) | Crash on missing photo / missing file (V14); silent KeyError on empty form (V17) |

---

## Next session — pick one

1. **Task 4** — fastest (5 marks), closes Part 1. ~15 mins of work.
2. **Task 1** — security requirements (10 marks). ~30 mins.
3. **Task 2** — threat model + DFD (15 marks). Need a diagram. ~45–60 mins.

After Part 1 is done, move to Part 2 (Authentication) — Flask-Login is already a dependency, so the implementation work in Task 7 is concrete and well-scoped.

---

## Notes for the team

- Repo is currently **Public** so CodeQL works. Can switch back to Private once Task 3 evidence screenshots are taken.
- The 7 figures in Task 3 are saved in `security-evidence/`. Keep them when committing.
- `ASSIGNMENT2_STATUS.md` (this file) lives at the repo root. Update the checklist as tasks finish.
- Final submission = a snapshot **tag** of this repo. Don't forget to `git tag` before the deadline.
