# One Assessment per analysis

`schemas.assessment.Assessment` is the canonical analytical document stored as
`assessment` for each job. Workers extend it as stages finish. Sections contain
main's existing outputs without changing their meaning:

| Sections | Producer |
| --- | --- |
| `contract_analysis`, `predicate_trees`, `effects`, `control_tracking_plan` | Static |
| `control_snapshot`, `resolved_control_graph` | Resolution |
| `effective_permissions`, `principal_labels`, `principal_history` | Policy |
| `recursive` | Per-contract Assessments from recursive resolution |

Version: `assessment/1`. Missing sections mean they were not published. Empty
collections, error objects, and null values inside sections retain their
original meaning. The validator checks the version and section shapes. Existing
component types describe nested records and transient inputs; they are no longer
independently persisted analytical documents.

Read through `db.assessment.load_assessment`. Stages can read or replace a section
through `get_assessment_section` and `store_assessment_section`. Updates lock the
job before reading and writing to prevent lost updates. The generic artifact
writer rejects the old analytical artifact names.

Existing capability, permission, label, and analysis-detail views preserve their
shapes. Authenticated operators can fetch
`/api/analyses/{run_name}/artifact/assessment` for the complete document. Existing
section URLs project from Assessment with their existing access rules. Runtime
readers do not fall back to legacy analytical rows. The analyses listing names
the physical `assessment` artifact; per-section URLs remain derived views.

Materializations store the same Assessment type restricted to static sections.
The cutover converts compatible main-version caches (analyzer era 6) to era 7
with verified payload preservation. Older eras remain stale and regenerate.
Static cache copies exclude resolved principals, permissions, and other
deployment-specific results. Existing
relational query tables remain derived indexes. Source files, transcripts,
diagnostics, and operational artifacts retain their separate storage.

## Cutover for saved results

No database reset is required. Back up the database and object storage, then:

1. Apply `alembic upgrade head`. This adds canonical materialization columns and
   retains the old columns without deleting data.
2. Stop old workers. Validate the compatible static-cache conversion with
   `python -m scripts.consolidate_materializations --dry-run`, then run
   `python -m scripts.consolidate_materializations`. The command reads back the
   converted payload before promoting an era 6 cache to era 7; legacy columns
   and blob objects remain intact.
3. Run `python -m scripts.consolidate_assessments --dry-run`, then
   `python -m scripts.consolidate_assessments`. For each job it copies the
   analytical sections and recursive results, hydrates available static inputs
   from the converted materializations, reads the stored Assessment back, and
   compares it before deleting old artifact rows. Complete era 6 static job
   results are promoted to era 7 after verification. Old blob objects remain.
   Unreadable bodies or conflicting sections abort without removing those rows.
4. Start the new workers/API. Caches older than the compatible source version
   rebuild on demand.

Both conversion commands are retryable. The job-artifact command accepts
`--job-id` for a scoped rehearsal. Matching
copies from interrupted runs are reverified before cleanup. Old writers must
remain stopped during cutover. Rolling back requires restoring the backup or
reconstructing old artifact rows from Assessment; reverting application code
alone is insufficient.

This change adds no temporal ledger, proposal simulation, inference rules, or
frontend redesign. The separately filed pipeline issues remain separate work.
