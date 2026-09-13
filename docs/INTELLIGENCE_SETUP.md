# NeuroShield intelligence, protection and research

## User workflow

The emerald/charcoal start screen presents **Connect Gmail** as the primary action. Once connected, it becomes **Open inbox**. An `.eml` import is a secondary path. An email opens a three-step review: Forensic Email DNA, Infrastructure & Campaign, and Protection Decision. Existing detailed forensic views remain below it.

Email inspection, Gmail ingestion, URL scans and extension policy checks use the backend intelligence wrapper. It records a privacy-reduced DNA representation, compares related incidents and checks analyst-approved IOCs. A missing backend produces an unverified state. Missing headers are not synthesized. Gmail OAuth remains read-only: the application does not claim to quarantine messages inside Gmail. Links in the NeuroShield text viewer are inert. The extension requests navigation/form restrictions and records its acknowledgement after applying them; a declared capability alone returns `PENDING`.

## Run and deploy

1. Install Node **22.13+**; Node 24 is recommended. The durable store uses built-in `node:sqlite`.
2. Run `npm ci`, copy `.env.example` to `.env`, and configure the existing Firebase/Google setup. See `GOOGLE_CLOUD_SETUP.md` for authorized domains and Gmail permissions.
3. Run `npm run dev`. For production, run `npm run build` and then `NODE_ENV=production npm start`.
4. Keep `data/intelligence.sqlite` on persistent storage, readable only by the service account. This implementation is for one SOC deployment, with one backend process managing HoneyTrap sessions. It is not a multi-tenant hosted service or distributed sandbox scheduler.

For a static frontend such as the existing Vercel site, deploy this Node backend separately. Set `VITE_API_BASE_URL=https://YOUR-BACKEND-ORIGIN` when building the frontend; set backend `CORS_ORIGINS` to the frontend's exact HTTPS origin. Configure the extension's API URL to the same backend. Leaving the variable empty uses same-origin APIs. The checked-in Vercel rewrite does **not** provide a Node/Docker backend.

The ordinary scan endpoints retain the repo's `REQUIRE_AUTH` configuration. SOC role checks apply even in public/demo scan mode. If enabling `REQUIRE_AUTH=true`, place the app behind an authenticated application gateway or provide a client credential flow; do not put service secrets into public `VITE_` variables. Use HTTPS for remote deployment and administrator credentials.

## SOC authorization

Set separate random secrets in server environment variables:

```dotenv
NEUROSHIELD_ADMIN_KEY=<independent-random-secret-at-least-32-characters>
NEUROSHIELD_ANALYST_KEY=<another-independent-random-secret-at-least-32-characters>
NEUROSHIELD_INTEL_DB=data/intelligence.sqlite
```

Open **Campaign intelligence** or **Controlled deception** and enter the issued SOC key. It remains only in page memory, is cleared on lock/reload, and is never written to localStorage. Server role checks use constant-time digest comparison; roles are not read from the request body. Key fingerprints identify review records. For individual accountability, replace these deployment keys with an organization identity provider and per-user roles before a multi-user production rollout.

| Capability | Analyst | Security administrator |
|---|---|---|
| Read campaigns, sessions and IOCs | Yes | Yes |
| Confirm/reject clusters and publish selected IOCs | Yes | Yes |
| Revoke a reviewed IOC | Yes | Yes |
| Enable/disable HoneyTrap | No | Yes |
| Launch/probe/stop a sandbox or trigger kill switch | No | Yes |

## Campaign fingerprinting and Adversarial DNA

DNA contains observable domain and URL structures, hashed sender/display patterns and wording, reported authentication results, header structure, relay indicators, attachment hashes/types, available browser structure/script hashes, form flags, and interpreted behavior/sequence features. DOM/input values, raw wording, email local parts and URL query values are not stored in the new intelligence database.

Observed input, inferred rules/similarity, and externally reported provider data have separate provenance labels. Authentication-Results and Received headers are recorded as header claims; they do not establish fresh signature verification or trustworthy attribution. Browser observations are sensor reports. This implementation does not identify a named phishing kit or a human attacker.

Correlation requires suspicious incidents, at least two feature families and a specific technical overlap. Weighted similarity must meet 0.60. Admission compares a new incident against every existing member, preventing unsupported transitive chains. Shared IP/ASN, geography or urgency alone cannot form a cluster. The score is a heuristic similarity confidence, **not a calibrated probability of common ownership**. Matching searches the latest 1,000 incidents from 30 days; clusters are capped at 100 members. Data remains stored when outside this matching window. Read endpoints have bounded result sets.

Repeated polling of the same observation is deduplicated within five minutes. Distinct Gmail message IDs remain distinct incidents even if wording is identical. Campaign IDs use `NS-CAMP-<random hex>`; evidence fingerprints use SHA-256.

Each cluster exposes every matching evidence item and an interactive graph. Analysts confirm or reject it with a rationale. **IOC checkboxes begin unselected.** A cluster confirmation never automatically blocks every sender, CDN or relay found in an email. Only selected, syntax-validated indicators are published. Exact observed destination domain/origin matches can affect future backend decisions. IP, relay and other shared infrastructure indicators remain contextual. IOCs expire after 30 days; revocation and cluster rejection retract their future use. New cluster members require another review and do not publish their new domains automatically. Existing clients may retain a previously issued decision for up to the extension's five-minute cache lifetime.

## Domain OSINT

The module accepts a public domain or HTTP(S) URL, extracts the domain, and performs bounded DNS A/AAAA/MX/NS/SPF/DMARC lookups. It queries fixed RDAP registries for `.com`, `.net`, `.org` and `.in`, and `ipwho.is` for public-IP network/hosting and approximate infrastructure country. Raw registrant contact entities are excluded. Provider requests are time-limited and size-limited; redirects are refused. No request is sent to a user-submitted website. Private, loopback, mapped, reserved and transition addresses are excluded from IOC use. Provider failures and unsupported suffixes remain explicitly unavailable.

Results include source, provenance and observation time, with a five-minute bounded cache. Cached DNS/network relationships enrich matching incidents and later detections. Certificate and live-redirect inspection are not performed by this passive module. It accepts certificate hashes or redirect observations when supplied by an independent browser sensor, but does not invent them. Hosting country is not attacker location.

## Controlled Deception / HoneyTrap

This is a **passive synthetic research workspace**. NeuroShield never emails a suspect, logs into a suspect website, submits credentials to a third party, opens an attacker URL, or automatically distributes a research capability. An administrator chooses a stored incident and explicitly creates the session. External interaction, if used within an authorized research exercise, enters through an expiring capability broker.

Build the isolated worker image on the backend host:

```sh
docker build -t neuroshield-honeytrap:local sandbox/honeytrap
```

The backend must have access to a dedicated Docker daemon. The worker receives no Docker socket, host volume, device or user file. For production isolation, run research on a dedicated worker host/VM with a separately reviewed management boundary; control of a host Docker daemon is security-sensitive. Do not add a host-execution fallback.

Every container uses network `none`, a read-only filesystem, UID/GID 10001, all capabilities dropped, `no-new-privileges`, 64 MiB memory, 0.25 CPU and a 32-process limit. No host port is published. Closed-schema JSON commands cross stdin/stdout; this allows controlled interaction while the sandbox has zero outbound networking. The image is not pulled automatically. The worker enforces an absolute deadline independently of the backend, so loss of the parent cannot create an unbounded session.

An administrator enables the module in the SOC view after runtime validation. Enablement is never restored across process restart. The launch gate requires all of:

- A stored `MALICIOUS` incident from the last 24 hours.
- Risk at least 85/100 and evidence confidence at least 90/100.
- Credential/payment behavior plus independent technical evidence, such as reported authentication failure, an external form destination, or an analyst-confirmed IOC.

The user cannot bypass this gate by posting risk/confidence values to the session endpoint. Duration must be 10–120 seconds. At most three sessions run concurrently; each accepts at most 60 interactions. Requests to the deception API are limited to 2 KiB.

The container issues an obviously synthetic persona using `example.invalid` and an `NS-SYNTHETIC-...` canary. The administrator sees a random 256-bit ingress capability once. Only its hash remains in process memory; the token is not saved to the database. The broker accepts a bearer capability at the returned `/api/deception/ingress/:id` endpoint. Its JSON schema is limited to:

```json
{"action":"portal"}
```

The other permitted actions are `script` and `canary`; `canary` requires the exact issued synthetic canary. No free-text messages, credentials, OTPs, personal data, arbitrary URLs, JavaScript or shell commands are accepted. Additional fields and unrecognized values are rejected without recording their contents. The synthetic portal and script are returned as inert JSON data, not executed in the SOC browser.

The SOC UI provides explicitly labeled **SOC probes** for checking the synthetic workspace. Probes do not count as attacker activity and do not create remote-infrastructure IOCs. Capability ingress records only the controlled resource action, timestamp, result and a public direct transport peer IP if present. Proxy forwarding headers are not trusted. The peer could be a proxy; it is never labeled a human identity. Accessing a canary may suggest collection behavior but is not proof of malicious intent. The workspace does not simulate nonexistent remote redirects or scripts.

The kill switch revokes all active capabilities, disables new sessions, terminates Docker clients and requests forced container removal. The worker deadline is an independent bound if Docker management becomes unavailable. Per-session stop and expiry do the same for that session. SOC review occurs after a session ends. Only selected validated observed IOCs enter threat intelligence; contextual peer IPs never become automatic blocks. Session timelines and reviews persist across restarts, while active capabilities do not.

## Verification

```sh
npm run test:intelligence
node --import tsx test/neuroshield_deterministic.test.ts
node --import tsx test/phase4_enforcement.test.ts
npm run lint
npm run build
```

The focused tests exercise synthetic-only input rejection, evidence gates, role enforcement through real HTTP routes, capability expiry/revocation, persistence/rollback, IOC confirmation/retraction, future backend protection and extension offline behavior. Worker protocol tests use a child process explicitly as a **test fixture**; they do not prove Docker isolation. There is no such fallback in the application.

Live Docker execution, real Google OAuth/Gmail integration, public-provider availability and visual browser QA must be verified in the deployment environment. The implementation workspace had no Docker runtime, and its browser could not access the isolated local server. No actual phishing infrastructure was contacted for testing.
