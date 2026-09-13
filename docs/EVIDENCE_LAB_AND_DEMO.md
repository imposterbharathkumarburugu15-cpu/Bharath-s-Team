# NeuroShield: Evidence Lab and security improvements

This change adds an inspectable, reproducible detection workflow. It does not establish uniqueness against all SIH teams or replace independent evaluation on real email datasets.

## Run the updated project

Use Node 22.13 or newer. Extract the source archive, open its folder in a terminal, and run:

```sh
npm ci
npm run dev
```

Open `http://localhost:3000/#lab`, or choose **Explore Evidence Lab** from the start screen. The lab works without API keys or Gmail access in the default public demo configuration. It requires the Node backend even when the frontend is hosted on Vercel.

If authentication is required, configure a randomly generated SOC key in the server environment, sign in through SOC Sector, and return to the lab. The default administrator and analyst credentials have been removed. Never put privileged keys in frontend code. Existing individual SOC keys still work.

If port 3000 is occupied, stop the other server or set a different `PORT`. PowerShell example:

```powershell
$env:PORT="3001"
npm run dev
```

Use `http://localhost:3001/#lab` in that case. Frontend requests now use the same origin. For separately hosted frontends, explicitly set `VITE_API_BASE_URL`. Hot reload uses the application's HTTP server instead of a separate fixed WebSocket port.

## What changed and why

| Change | What it does | Why it matters |
| --- | --- | --- |
| Evidence Lab | Runs the core engine once on the original input, then again after removing wording, sender context, and destination evidence separately | A judge can challenge the result and see which evidence changes the decision |
| Destination integrity detector | Parses HTML5, compares URL labels and actual targets, accounts for base URLs, inspects password forms and submit-button overrides | Reveals deception that a plain-text summary or naive link regex can miss |
| Decision receipts | Exports policy version, verdict, signal tags and ablation results with a canonical SHA-256 checksum | A compact decision record can be compared later without exporting the message or raw destinations |
| Synthetic evaluation | Executes nine authored positive, benign and missing-input cases | Exposes regressions and false positives rather than showing a hardcoded success percentage |
| Authentication fix | Removes built-in privileged credentials and the one-click administrator unlock | Public knowledge of a default key can no longer grant SOC privileges |
| Honest SOC state | Removes browser mock incidents and fake sandbox fallbacks on errors | Backend failures and missing Docker stay visible; research simulation cannot impersonate real telemetry |
| Email context fixes | Retains subject, identity, headers, sender display name, HTML and empty body semantics | The detectors receive context that the earlier normalization path discarded |
| Authentication evidence fixes | DMARC failure survives SPF/DKIM PASS; repeated header values work; metadata-only failure contributes risk | Inconsistent authentication evidence cannot silently collapse into PASS or zero risk |
| Server integration | Same-origin API handling, shared HMR server, useful port collision error, removal of substring-based localhost CORS exception | Alternate-port development works and explicit origin configuration is respected |

## A three-minute judge demonstration

1. Open **Evidence Lab**, keep the disguised document link selected, and click **Analyze & challenge verdict**. Show that the visible host and destination differ. The authored example scores 45, which recommends review.
2. Point to **Without link / form evidence**. Its score drops to 0 on this example. Explain: “That identifies the evidence responsible for this warning. Removing evidence does not make the original message safe.” The narrative-only and sender-only ablations retain the mismatch.
3. Select **The submit button changes the destination**. The form appears local, but the button's `formaction` sends the password to another origin. Show the structural evidence and score 65. Cross-origin SSO may be legitimate; the destination requires verification.
4. Select **A password travels without encryption**. Show the password form's HTTP destination and score 85. No credentials were entered or transmitted.
5. Run the nine-case evaluation. Show the ordinary urgent meeting message remains allowed and empty input returns UNKNOWN. Explain that these are authored regression controls, not a real-world accuracy benchmark.
6. Export a receipt and verify its checksum. Change its risk score in a text editor without changing the digest, then upload it: verification fails. Preserve a trusted original digest separately; a checksum is not a digital signature.

Suggested explanation: **“NeuroShield lets an analyst inspect the destination, challenge the verdict by removing evidence, and preserve a minimal decision record. The demonstration is repeatable without an external model API.”**

## Scope and honest limitations

- This addition uses local deterministic rules. It does not train a new model or claim better accuracy than ChatGPT, Claude, Gemini, or competing teams.
- The destination detector is integrated into `NeuroShieldCore.analyze`, not limited to the lab. Callers must supply HTML through normalized email body HTML or `metadata.html`; web form comparisons also need `metadata.pageUrl`. Existing extension telemetry is not expanded by this change.
- Static HTML parsing does not execute scripts, inspect QR images, follow redirects, render CSS or establish ownership of a host. Password fields associated with forms outside their descendant tree and script-created forms require further coverage. A mismatch is evidence for review, not proof of a malicious operator.
- Policy floors are explicit heuristics: visible-host mismatch 45, external password destination / active link scheme 65, unencrypted password submission 85. Core evidence can raise the final score further.
- Authentication results are supplied claims. This change does not independently verify DKIM signatures or establish a trusted receiving-MTA boundary.
- Ablation is a sensitivity experiment, not causal attribution or a calibrated explanation of a trained model. The existing core coverage metric is displayed as-is.
- The lab does not contact destinations, use OSINT/IOC enrichment, persist incidents, execute protection actions, or invoke an LLM. Other existing application routes can still use configured external services.
- Receipts intentionally omit original message content, sender addresses, destinations and raw evidence. The digest covers only the exported decision receipt. It does not prove origin, link to an original email, or certify detector correctness.
- HoneyTrap still requires the actual isolated Docker runtime and an administrator. Missing runtime is reported honestly.
- This is a targeted improvement, not a complete security audit. Existing system-wide production readiness, authentication boundaries and unmodified features need independent review.

## Verification

```sh
npm run lint
npm run test:security
npm run build
```

At delivery: TypeScript check passed; 33 security tests passed (12 new and 21 existing); all 9 synthetic evaluation expectations passed; production frontend and backend build passed. API behavior was exercised through real HTTP integration tests. Browser visual QA, live Gmail, deployed extension enforcement, external providers and Docker isolation were not exercised in this session. Vite still reports a large frontend bundle warning.

New tests cover HTML entity decoding, nested link text, base URLs, submit overrides, ordinary external links, relative forms, hidden text, bounded input, active schemes, subject-only requests, conflicting authentication, empty input, network-free analysis, receipt privacy and tampering, HTTP validation and rejection of the formerly published SOC keys.

## API

All routes inherit the existing authentication and rate-limit middleware. Lab JSON input is capped at 128 KB; text fields have smaller explicit bounds.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/lab/cases` | List the synthetic cases |
| POST | `/api/lab/analyze` | Analyze `{source, content, subject?, from?, html?, pageUrl?}` and run three ablations |
| POST | `/api/lab/evaluate` | Execute the fixed synthetic suite |
| POST | `/api/lab/verify` | Check an exported receipt envelope's checksum |

The branch is `feat/evidence-lab-security`. The downloaded source archive contains these changes. They were not pushed to GitHub or deployed.
