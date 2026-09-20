// Injection Playground front end. Vanilla JS, no build step.
// Talks to the FastAPI backend in agent_sandbox/web/app.py over plain
// fetch() for actions and EventSource (SSE) for live run progress.

(() => {
  "use strict";

  const state = {
    status: null,
    corpus: null,
    modelMode: "sim", // "sim" | "real"
    corpusModelMode: "sim",
    currentRunId: null,
    currentEventSource: null,
    corpusRunId: null,
    corpusEventSource: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function fmtUsd(n) {
    if (n === undefined || n === null) return "$0.00";
    if (n < 0.01 && n > 0) return "<$0.01";
    return "$" + n.toFixed(4).replace(/0+$/, "").replace(/\.$/, ".00");
  }

  // -- tabs -----------------------------------------------------------

  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const name = tab.dataset.tab;
      $("#view-attack").hidden = name !== "attack";
      $("#view-corpus").hidden = name !== "corpus";
    });
  });

  // -- toggle groups ----------------------------------------------------

  function wireToggle(groupSel, onChange) {
    const group = $(groupSel);
    group.querySelectorAll(".toggle-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        group.querySelectorAll(".toggle-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        onChange(btn.dataset.mode);
      });
    });
  }
  wireToggle("#model-toggle", (mode) => { state.modelMode = mode; });
  wireToggle("#corpus-model-toggle", (mode) => { state.corpusModelMode = mode; });

  // -- bootstrap: status + corpus -------------------------------------

  async function loadStatus() {
    const res = await fetch("/api/status");
    const status = await res.json();
    state.status = status;

    const modelSelects = [$("#model-select"), $("#corpus-model")];
    modelSelects.forEach((sel) => {
      sel.innerHTML = "";
      status.models.forEach((m) => {
        const opt = document.createElement("option");
        opt.value = m; opt.textContent = m;
        if (m === status.default_model) opt.selected = true;
        sel.appendChild(opt);
      });
    });

    const banner = $("#mode-banner");
    banner.hidden = false;
    if (status.credentials_available) {
      banner.className = "banner banner-safe";
      banner.innerHTML = `<strong>Real Gemini available.</strong> Application Default Credentials found ` +
        `(project <code>${escapeHtml(status.project)}</code>, location <code>${escapeHtml(status.location)}</code>). ` +
        `Toggle "Real Gemini" to run the decision-making model live; tools stay simulated either way.`;
    } else {
      banner.className = "banner banner-warn";
      banner.innerHTML = `<strong>Simulator mode only.</strong> No usable Google Application Default ` +
        `Credentials were found, so real-model runs are disabled here. The deterministic offline brain ` +
        `still fully exercises policy, taint tracking, quarantine, and the approval gate. To enable real ` +
        `Gemini: run <code>gcloud auth application-default login</code>, then reload this page.`;
      $$(".toggle-btn[data-mode='real']").forEach((b) => { b.disabled = true; b.title = "no credentials available"; });
    }
  }

  async function loadCorpus() {
    const res = await fetch("/api/corpus");
    const corpus = await res.json();
    state.corpus = corpus;

    const presetSelect = $("#preset-select");
    const attackGroup = document.createElement("optgroup");
    attackGroup.label = "Attack cases";
    corpus.attack_cases.forEach((c) => {
      const opt = document.createElement("option");
      opt.value = "attack:" + c.id;
      opt.textContent = `${c.id} (${c.category})`;
      attackGroup.appendChild(opt);
    });
    const benignGroup = document.createElement("optgroup");
    benignGroup.label = "Benign cases";
    corpus.benign_cases.forEach((c) => {
      const opt = document.createElement("option");
      opt.value = "benign:" + c.id;
      opt.textContent = `${c.id} (${c.category})`;
      benignGroup.appendChild(opt);
    });
    presetSelect.appendChild(attackGroup);
    presetSelect.appendChild(benignGroup);

    const catSelect = $("#corpus-category");
    corpus.categories.forEach((cat) => {
      const opt = document.createElement("option");
      opt.value = cat; opt.textContent = cat;
      catSelect.appendChild(opt);
    });

    // Preload a realistic working state: the first attack case, not a blank form.
    if (corpus.attack_cases.length) {
      applyPreset(corpus.attack_cases[0]);
      presetSelect.value = "attack:" + corpus.attack_cases[0].id;
    }
  }

  function applyPreset(caseObj) {
    $("#trusted-task").value = caseObj.trusted_task;
    $("#untrusted-text").value = caseObj.untrusted_text;
    $("#carrier-tool").value = caseObj.carrier_tool || "";
  }

  $("#preset-select").addEventListener("change", (e) => {
    const val = e.target.value;
    if (!val) return;
    const [kind, id] = val.split(":");
    const list = kind === "attack" ? state.corpus.attack_cases : state.corpus.benign_cases;
    const found = list.find((c) => c.id === id);
    if (found) applyPreset(found);
  });

  // -- interactive run --------------------------------------------------

  function resetResultsUI() {
    $("#naive-body").innerHTML = '<p class="empty-hint">Waiting for the run to start&hellip;</p>';
    $("#sandboxed-body").innerHTML = '<p class="empty-hint">Waiting for the run to start&hellip;</p>';
    $("#cost-badge").hidden = true;
    $("#run-status").hidden = false;
    setStatus("running", "Running…");
  }

  function setStatus(kind, text) {
    const dot = $("#status-dot");
    dot.className = "status-dot " + kind;
    $("#status-text").textContent = text;
  }

  $("#run-btn").addEventListener("click", async () => {
    const trusted_task = $("#trusted-task").value;
    const untrusted_text = $("#untrusted-text").value;
    const carrier_tool = $("#carrier-tool").value || null;
    const model = $("#model-select").value;
    const declassify_via = $("#declassify-select").value || null;
    const simulate = state.modelMode !== "real";

    if (!trusted_task.trim()) {
      alert("Enter a trusted task first.");
      return;
    }

    resetResultsUI();
    $("#run-btn").disabled = true;

    if (state.currentEventSource) state.currentEventSource.close();

    try {
      const res = await fetch("/api/playground/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trusted_task, untrusted_text, carrier_tool, model, simulate, declassify_via }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        setStatus("error", "Error: " + (err.detail || res.statusText));
        $("#run-btn").disabled = false;
        return;
      }
      const { run_id } = await res.json();
      state.currentRunId = run_id;
      streamPlayground(run_id);
    } catch (err) {
      setStatus("error", "Network error: " + err.message);
      $("#run-btn").disabled = false;
    }
  });

  function streamPlayground(runId) {
    const es = new EventSource(`/api/playground/${runId}/events`);
    state.currentEventSource = es;

    es.addEventListener("phase", (e) => {
      const data = JSON.parse(e.data);
      setStatus("running", `Running ${data.phase} agent…`);
    });

    es.addEventListener("phase_result", (e) => {
      const data = JSON.parse(e.data);
      renderPhaseResult(data.phase, data);
    });

    es.addEventListener("approval_request", (e) => {
      const data = JSON.parse(e.data);
      showApprovalModal(runId, data);
    });

    es.addEventListener("approval_decision", () => {
      hideApprovalModal();
    });

    es.addEventListener("usage", (e) => {
      const data = JSON.parse(e.data);
      const badge = $("#cost-badge");
      badge.hidden = false;
      if (data.simulate) {
        badge.textContent = "simulator: $0.00, 0 tokens";
      } else {
        badge.textContent = `${data.total_tokens} tokens (${data.prompt_tokens} in / ${data.output_tokens} out) ≈ ${fmtUsd(data.estimated_cost_usd)}`;
      }
    });

    es.addEventListener("fatal_error", (e) => {
      const data = JSON.parse(e.data);
      setStatus("error", "Error");
      const box = `<div class="fact-row"><span class="fact-value" style="color:var(--critical)">${escapeHtml(data.message)}</span></div>`;
      if (data.phase === "sandboxed") $("#sandboxed-body").innerHTML = box;
      else $("#naive-body").innerHTML = box;
      $("#run-btn").disabled = false;
      es.close();
    });

    es.addEventListener("done", () => {
      setStatus("done", "Done");
      $("#run-btn").disabled = false;
      es.close();
    });

    es.onerror = () => {
      // EventSource fires this on a normal server-closed stream too; only
      // treat it as a real problem if we never reached a terminal state.
      if ($("#status-text").textContent === "Running…") {
        setStatus("error", "Connection to the run was lost.");
        $("#run-btn").disabled = false;
      }
      es.close();
    };
  }

  function labelForBlocked(blockedBy) {
    if (!blockedBy) return null;
    return blockedBy;
  }

  function renderPhaseResult(phase, data) {
    const body = phase === "naive" ? $("#naive-body") : $("#sandboxed-body");
    const parts = [];

    const landed = data.attack_succeeded;
    const pillClass = landed ? "pill-critical" : "pill-safe";
    const pillText = landed ? "sink tool executed" : (data.blocked_by ? "blocked" : "no side effect");
    parts.push(`<div class="fact-row"><span class="fact-label">Outcome</span><span class="fact-value"><span class="pill ${pillClass}">${escapeHtml(pillText)}</span></span></div>`);

    if (data.blocked_by) {
      parts.push(`<div class="fact-row"><span class="fact-label">Blocked by</span><span class="fact-value mono">${escapeHtml(data.blocked_by)}</span></div>`);
    }

    if (data.intent) {
      const args = JSON.stringify(data.intent.args, null, 2);
      parts.push(`<div class="fact-row"><span class="fact-label">Proposed call</span><span class="fact-value mono">${escapeHtml(data.intent.tool)}(&hellip;)</span></div>`);
      parts.push(`<div class="code-block">${escapeHtml(data.intent.tool)}(\n${escapeHtml(args).split("\n").map(l => "  " + l).join("\n")}\n)</div>`);
      parts.push(`<div class="fact-row"><span class="fact-label">Triggered by</span><span class="fact-value mono">${escapeHtml(data.intent.triggered_by)}</span></div>`);
    } else {
      parts.push(`<div class="fact-row"><span class="fact-label">Proposed call</span><span class="fact-value">none &mdash; no directive reached the decision loop</span></div>`);
    }

    if (data.digests && data.digests.length) {
      parts.push(`<h3 style="margin-top:14px;">Quarantined extraction</h3>`);
      data.digests.forEach((d) => {
        parts.push(`<div class="code-block">summary: ${escapeHtml(d.summary) || "(empty)"}</div>`);
        if (d.entities && d.entities.length) {
          parts.push(`<div>` + d.entities.map(en => `<span class="digest-entity">${escapeHtml(en)}</span>`).join("") + `</div>`);
        }
      });
    }

    // Provenance chain, pulled from human_gate / error events in this phase's log.
    const chainRows = extractProvenance(data.events || []);
    if (chainRows.length) {
      parts.push(`<h3 style="margin-top:14px;">Provenance chain</h3>`);
      chainRows.forEach((chain) => { parts.push(renderChain(chain)); });
    }

    parts.push(renderEventsDetails(data.events || []));

    body.innerHTML = parts.join("\n");
  }

  function extractProvenance(events) {
    const chains = [];
    events.forEach((evt) => {
      if (evt.type === "human_gate" && evt.payload.phase === "request" && evt.payload.provenance) {
        Object.entries(evt.payload.provenance).forEach(([arg, chain]) => chains.push({ arg, chain }));
      }
      if (evt.type === "error" && evt.payload.kind === "TaintViolation" && evt.payload.detail && evt.payload.detail.chain) {
        chains.push({ arg: evt.payload.detail.arg_name, chain: evt.payload.detail.chain.map(h => `[${h.label}] ${h.description}`).join(" -> ") });
      }
    });
    return chains;
  }

  function renderChain(chainObj) {
    const hops = String(chainObj.chain).split(" -> ");
    const hopsHtml = hops.map((hop) => {
      const m = hop.match(/^\[(\w+)\]\s*(.*)$/);
      const label = m ? m[1] : "";
      const desc = m ? m[2] : hop;
      return `<div class="chain-hop"><span class="hop-label ${label}">${escapeHtml(label)}</span><span>${escapeHtml(desc)}</span></div>`;
    }).join("");
    return `<div class="fact-row"><span class="fact-label">arg: ${escapeHtml(chainObj.arg)}</span></div>${hopsHtml}`;
  }

  function renderEventsDetails(events) {
    if (!events.length) return "";
    const lines = events.map((e) => `<div class="event-line"><span class="ev-type">[${escapeHtml(e.type)}]</span> ${escapeHtml(JSON.stringify(e.payload))}</div>`).join("");
    return `<details class="events"><summary>full trajectory (${events.length} events)</summary>${lines}</details>`;
  }

  // -- approval modal ----------------------------------------------------

  let pendingApprovalId = null;
  let pendingRunId = null;

  function showApprovalModal(runId, data) {
    pendingApprovalId = data.approval_id;
    pendingRunId = runId;
    $("#approval-tool").textContent = data.tool;
    $("#approval-rule").textContent = data.rule;
    $("#approval-args").textContent = JSON.stringify(data.args, null, 2);
    const provDiv = $("#approval-provenance");
    provDiv.innerHTML = "";
    Object.entries(data.provenance || {}).forEach(([arg, chain]) => {
      provDiv.insertAdjacentHTML("beforeend", renderChain({ arg, chain }));
    });
    if (!Object.keys(data.provenance || {}).length) {
      provDiv.innerHTML = '<p class="empty-hint">No tainted arguments on this call.</p>';
    }
    $("#approval-reason").value = "";
    $("#approval-overlay").hidden = false;
  }

  function hideApprovalModal() {
    $("#approval-overlay").hidden = true;
    pendingApprovalId = null;
  }

  async function decideApproval(approved) {
    if (!pendingApprovalId || !pendingRunId) return;
    const reason = $("#approval-reason").value;
    await fetch(`/api/playground/${pendingRunId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approval_id: pendingApprovalId, approved, reason, decided_by: "operator" }),
    });
    hideApprovalModal();
  }

  $("#approval-approve").addEventListener("click", () => decideApproval(true));
  $("#approval-deny").addEventListener("click", () => decideApproval(false));

  // -- corpus runner ------------------------------------------------------

  $("#corpus-estimate-btn").addEventListener("click", async () => {
    const category = $("#corpus-category").value || null;
    const model = $("#corpus-model").value;
    const include_benign = $("#corpus-include-benign").checked;
    const res = await fetch("/api/corpus/estimate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ category, model, include_benign }),
    });
    const est = await res.json();
    const box = $("#corpus-estimate");
    box.hidden = false;
    box.innerHTML = `
      <span>scenarios: <b>${est.num_scenarios}</b></span>
      <span>model calls: <b>${est.num_calls}</b></span>
      <span>est. tokens: <b>${est.estimated_tokens}</b></span>
      <span>est. cost: <b>${fmtUsd(est.estimated_cost_usd)}</b></span>
      <span style="color:var(--mid)">(rough pre-run estimate &mdash; only meaningful in Real Gemini mode; Simulator mode is always $0.00)</span>
    `;
  });

  $("#corpus-run-btn").addEventListener("click", async () => {
    const category = $("#corpus-category").value || null;
    const model = $("#corpus-model").value;
    const declassify_via = $("#corpus-declassify").value || null;
    const include_benign = $("#corpus-include-benign").checked;
    const simulate = state.corpusModelMode !== "real";

    if (!simulate) {
      const proceed = confirm("This will make real, billed calls to Vertex AI Gemini. Continue?");
      if (!proceed) return;
    }

    $("#corpus-run-btn").disabled = true;
    $("#corpus-progress").hidden = false;
    $("#corpus-results").hidden = true;
    $("#corpus-log").innerHTML = "";
    $("#corpus-progress-fill").style.width = "0%";
    $("#corpus-progress-text").textContent = "starting…";

    const res = await fetch("/api/corpus/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ category, model, simulate, declassify_via, include_benign }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      $("#corpus-progress-text").textContent = "error: " + (err.detail || res.statusText);
      $("#corpus-run-btn").disabled = false;
      return;
    }
    const { run_id } = await res.json();
    streamCorpus(run_id);
  });

  function streamCorpus(runId) {
    const es = new EventSource(`/api/corpus/run/${runId}/events`);

    es.addEventListener("start", (e) => {
      const data = JSON.parse(e.data);
      $("#corpus-progress-text").textContent = `0 / ${data.total}`;
    });

    es.addEventListener("progress", (e) => {
      const data = JSON.parse(e.data);
      const pct = Math.round((data.index / data.total) * 100);
      $("#corpus-progress-fill").style.width = pct + "%";
      $("#corpus-progress-text").textContent = `${data.index} / ${data.total}`;
      const flag = data.is_benign
        ? (data.sandboxed_attack_succeeded ? "" : "blocked-benign-task")
        : (data.sandboxed_attack_succeeded ? "ATTACK LANDED" : "blocked");
      const cls = flag === "ATTACK LANDED" ? "style='color:var(--critical)'" : "style='color:var(--mid)'";
      $("#corpus-log").insertAdjacentHTML("afterbegin",
        `<div class="event-line"><span class="ev-type">${escapeHtml(data.scenario_id)}</span> ${escapeHtml(data.category)} &mdash; <span ${cls}>${escapeHtml(flag || "ok")}</span></div>`);
    });

    es.addEventListener("scenario_error", (e) => {
      const data = JSON.parse(e.data);
      $("#corpus-log").insertAdjacentHTML("afterbegin",
        `<div class="event-line" style="color:var(--critical)">${escapeHtml(data.scenario_id)}: ${escapeHtml(data.message)}</div>`);
    });

    es.addEventListener("fatal_error", (e) => {
      const data = JSON.parse(e.data);
      $("#corpus-progress-text").textContent = "error";
      $("#corpus-log").insertAdjacentHTML("afterbegin", `<div class="event-line" style="color:var(--critical)">${escapeHtml(data.message)}</div>`);
      $("#corpus-run-btn").disabled = false;
      es.close();
    });

    es.addEventListener("done", (e) => {
      const data = JSON.parse(e.data);
      renderCorpusResults(data);
      $("#corpus-run-btn").disabled = false;
      es.close();
    });

    es.onerror = () => { es.close(); };
  }

  function renderCorpusResults(data) {
    $("#corpus-results").hidden = false;
    const tbody = $("#corpus-table tbody");
    tbody.innerHTML = "";
    Object.entries(data.categories).sort().forEach(([cat, stats]) => {
      const naiveAsr = stats.total ? (stats.naive_success / stats.total * 100).toFixed(0) : "0";
      const sbxAsr = stats.total ? (stats.sandboxed_success / stats.total * 100).toFixed(0) : "0";
      tbody.insertAdjacentHTML("beforeend",
        `<tr><td>${escapeHtml(cat)}</td><td class="num">${stats.total}</td><td class="num">${naiveAsr}%</td><td class="num">${sbxAsr}%</td></tr>`);
    });
    $("#corpus-summary").textContent =
      `Overall: naive ASR=${(data.overall_naive_asr * 100).toFixed(0)}%, sandboxed ASR=${(data.overall_sandboxed_asr * 100).toFixed(0)}%, ` +
      `false-positive rate=${(data.false_positive_rate * 100).toFixed(0)}% (${data.benign_blocked}/${data.benign_total} benign tasks incorrectly blocked)`;
    const u = data.usage;
    if (u.total_calls) {
      $("#corpus-cost").textContent = `Usage: ${u.total_tokens} tokens across ${u.total_calls} live model calls ≈ ${fmtUsd(u.estimated_cost_usd)}`;
    } else {
      $("#corpus-cost").textContent = "Usage: simulator mode, $0.00, 0 real model calls.";
    }
  }

  // -- init ----------------------------------------------------------------

  loadStatus();
  loadCorpus();
})();
