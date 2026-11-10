// Overview `analysis_provenance` and inventory `analysis_state` tokens. An
// unlisted token renders raw, never as a guessed word.

const ND = "not_determined";

export function provenanceDate(iso) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function provenanceDateTime(iso) {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? new Date(ms).toLocaleString() : null;
}

const shortJob = (id) => String(id).slice(0, 8);

// The analyzer version with the job's state; `older_analyzer` is the flag.
function analyzerWord(job) {
  const version = job.static_analyzer_version;
  const state = job.state;
  const v = typeof version === "number" ? `v${version}` : null;
  if (state === "older_analyzer") return v ? `older analyzer ${v}` : "older analyzer · version not determined";
  const head = v ? `analyzer ${v}` : version === ND ? "analyzer version not determined" : null;
  if (state === "current_analyzer" || state == null) return head;
  const stateWord = state === ND ? "analyzer state not determined" : state;
  return [head, stateWord].filter(Boolean).join(" · ");
}

function passWord(job, label = "last pipeline pass") {
  const at = job.last_pipeline_pass_at;
  if (at == null) return null;
  if (at === ND) return `${label} not determined`;
  const date = provenanceDate(at);
  return date ? `${label} ${date}` : at;
}

function reuseWord(job) {
  const donor = job.static_reused_from_job_id;
  if (donor == null) return null;
  return donor === ND ? "static reuse not determined" : `reused from job ${shortJob(donor)}`;
}

function allNotDetermined(job) {
  return [job.state, job.static_analyzer_version, job.last_pipeline_pass_at].every((v) => v === ND);
}

function jobText(job) {
  if (allNotDetermined(job)) return "analysis provenance not determined";
  return [analyzerWord(job), reuseWord(job), passWord(job)].filter(Boolean).join(" · ");
}

function timeWord(label, value) {
  if (value == null) return null;
  if (value === ND) return `${label} not determined`;
  return `${label} ${provenanceDateTime(value) || value}`;
}

function jobTitle(job, prefix) {
  const donor = job.static_reused_from_job_id;
  return [
    `${prefix}job ${job.job_id}`,
    analyzerWord(job),
    donor && donor !== ND ? `static analysis reused from job ${donor}` : reuseWord(job),
    timeWord("started", job.started_at),
    timeWord("last pipeline pass", job.last_pipeline_pass_at),
  ]
    .filter(Boolean)
    .join(" · ");
}

// One line for an overview entry, with a full-detail title. For a proxy the
// implementation's job follows compactly. Null when the entry carries no
// provenance. Shape: {text, title}.
export function analysisProvenanceLine(entry) {
  const prov = entry?.analysis_provenance;
  const job = prov?.job;
  const impl = prov?.impl_job;
  if (!job && !impl) return null;
  const parts = [];
  const titles = [];
  if (job) {
    parts.push(jobText(job));
    titles.push(jobTitle(job, ""));
  }
  if (impl) {
    const implText = allNotDetermined(impl)
      ? "not determined"
      : [analyzerWord(impl), reuseWord(impl), passWord(impl, "last pass")].filter(Boolean).join(" · ");
    parts.push(`impl: ${implText}`);
    titles.push(jobTitle(impl, "implementation "));
  }
  return { text: parts.join(" · "), title: titles.join("\n") };
}

const INVENTORY_CHIP = {
  current_analyzer: { text: "analyzed", tone: "ok" },
  older_analyzer: { text: "analyzed · older analyzer", tone: "ok" },
  analysis_failed: { text: "analysis failed", tone: "err" },
  analysis_not_completed: { text: "analysis not completed", tone: "pending" },
};

// The /addresses row's analysis chip. Shape: {text, tone, title}.
export function inventoryAnalysisChip(row) {
  const token = row?.analysis_state;
  if (token == null) return row?.analyzed ? INVENTORY_CHIP.current_analyzer : INVENTORY_CHIP.analysis_not_completed;
  const chip = INVENTORY_CHIP[token] || { text: token, tone: "pending" };
  if (token !== "older_analyzer") return { ...chip, title: undefined };
  const version = row.stale_analysis_version;
  // The backend files an analysis it can't prove current as older; without a version that is all it knows.
  if (typeof version !== "number") return { text: "analyzed · analyzer version not determined", tone: "ok", title: undefined };
  return { ...chip, title: `static analyzer v${version}` };
}
