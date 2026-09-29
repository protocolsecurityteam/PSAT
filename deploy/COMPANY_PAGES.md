# Prepared company responses

`PSAT_PREPARED_COMPANY_PAGES=1` makes overview, functions, and summary reads use
compressed PostgreSQL responses. The web entrypoint supervises the API and one
separate `workers.company_pages` process. Preparation does not run in the
analysis workers group and does not wake or extend that group's lifetime.

The builder polls lightweight identity/revision metadata every five seconds.
It processes one company at a time, using a row lock with `SKIP LOCKED` so other
replicas can prepare different companies. A process exit releases the claim.
Failed builds retain previous bytes, back off for 5–300 seconds, and leave other
companies eligible. An API failure exits the supervisor; a builder failure is
restarted independently. Processes share the VM's CPU and memory.

Each section records dependency tokens from the same repeatable-read snapshot
used by its queries, including queries in borrowed database connections.
Source writes change revision tokens transactionally. Unchanged responses have
no age-based rebuild. A change during preparation remains dirty after publication.
Overview-only balance/upgrade changes do not rebuild functions; TVL and pending
analysis counts refresh the separate `/api/company/{name}/summary` response.
Legacy `Job.company` pages also prepare in the background, with conservative
job-graph invalidation. Modern protocol caches use per-protocol dependencies.

Both public and authenticated reads validate the same source revisions. Missing,
dirty, or incompatible responses return `503` with `code: company_preparing`,
`Retry-After: 2`, and `private, no-store`; they never trigger live graph building.
The browser retries this specific response up to 15 times at two-second intervals
and then exposes its normal error state. `Cache-Control: no-cache` revalidates the stored data.
An authorized `POST /api/company/{name}/refresh` marks the shared preparation dirty
and returns `202`; it does not build inside the request. Credential-bearing
responses retain the origin's private-cache policy. Anonymous edge responses can
remain cached for up to 60 seconds; successful publication enqueues a durable
purge for every section and encoding under the company tag.

The response version hashes the shared Python implementation, JSON configuration,
and dependency lock plus supported chain IDs. Documentation/frontend/CI-only
changes can reuse saved data. `PSAT_COMPANY_BUILD_REVISION` is an optional explicit
invalidation marker. Disabling `PSAT_PREPARED_COMPANY_PAGES` restores the previous
live endpoints as a rollback path; it also stops starting the colocated builder.

To move preparation off the web VM later, run `python -m workers.company_pages`
in a dedicated, supervised process group with the same application build,
database, and cache-purge configuration. Set `PSAT_COMPANY_BUILDER_ON_WEB=0` on web
machines, leaving `PSAT_PREPARED_COMPANY_PAGES=1` on both roles. Keep a builder warm
if preparation latency matters. Database row claims coordinate all replicas.

Before production rollout, exercise the supervisor on a staging VM matching the
web machine's size under concurrent API traffic. Measure combined peak memory,
API tail latency, build duration, retry/failure logs, and database connections.
Sequential preparation bounds concurrent graphs but is not a hard memory quota
for an individual growing company. Increase web RAM or move the consumer if the
combined workload loses headroom. Logs include company, sections, duration, and
compressed bytes; the `company_pages` heartbeat reports preparation outcomes.

The PR's first migration now follows main's latest migration to retain the
repository's linear history. Preview databases that previously installed the
older PR history must be recreated before upgrading; production main has not
installed those PR-only revisions. The final migration can downgrade by dropping
legacy prepared rows and the section-specific columns; source records are kept.
