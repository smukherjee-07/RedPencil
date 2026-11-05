/**
 * frontend/app.js
 * Client logic coordinating API requests, status polling, and approvals.
 */

const API_BASE = "/api";
let activeApprovalId = null;

const assessmentForm = document.getElementById("assessmentForm");
const planOutput = document.getElementById("planOutput");
const executionTimeline = document.getElementById("executionTimeline");
const findingsBody = document.getElementById("findingsBody");
const approvalModal = document.getElementById("approvalModal");
const modalDetails = document.getElementById("modalDetails");
const analystNotes = document.getElementById("analystNotes");
const modelSelect = document.getElementById("modelSelect");
const modelStatus = document.getElementById("modelStatus");

assessmentForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const promptText = document.getElementById("promptInput").value;
    const targets = document.getElementById("targetInput").value.split(",").map(s => s.trim()).filter(Boolean);
    const exclusions = document.getElementById("excludedInput").value.split(",").map(s => s.trim()).filter(Boolean);

    planOutput.textContent = "Validating target scope and building assessment plan...";

    try {
        const res = await fetch(`${API_BASE}/assessment/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                request_text: promptText,
                authorized_targets: targets,
                excluded_targets: exclusions,
                selected_model: modelSelect.value || null,
            })
        });

        if (!res.ok) {
            const err = await res.json();
            planOutput.textContent = `Error: ${err.detail || "Unable to start assessment."}`;
            return;
        }

        const data = await res.json();
        renderPlan(data.plan);
        planOutput.textContent += `\nStatus: ${data.status}\n${data.message || ""}`;
        pollStatus();
    } catch (err) {
        planOutput.textContent = `Network failure: ${err.message}`;
    }
});

function renderPlan(plan) {
    let output = "=== PROPOSED ASSESSMENT PLAN (NO SCANS RUN) ===\n";
    plan.forEach(step => {
        output += `Stage ${step.stage}: [${step.tool}] on target ${step.target}\nPlanning source: ${step.planning_source || "Unknown"}\nRationale: ${step.rationale}\n\n`;
    });
    if (!plan || plan.length === 0) output += "No tools were recommended.\n";
    planOutput.textContent = output;
}

async function loadModels() {
    try {
        const response = await fetch(`${API_BASE}/models`);
        if (!response.ok) throw new Error("Model list request failed.");
        const data = await response.json();
        modelSelect.replaceChildren();

        if (!data.models || data.models.length === 0) {
            const option = document.createElement("option");
            option.value = "";
            option.textContent = `${data.configured_model || "Default model"} (not available locally)`;
            modelSelect.appendChild(option);
            modelSelect.disabled = true;
            modelStatus.textContent = data.message || "No local models found; the rule-based planner will be used.";
            return;
        }

        data.models.forEach(model => {
            const option = document.createElement("option");
            option.value = model;
            option.textContent = model === data.default ? `${model} (default)` : model;
            option.selected = model === data.default;
            modelSelect.appendChild(option);
        });
        modelSelect.disabled = false;
        modelStatus.textContent = `Found ${data.models.length} local Ollama model${data.models.length === 1 ? "" : "s"}.`;
    } catch (error) {
        modelSelect.replaceChildren();
        const option = document.createElement("option");
        option.value = "";
        option.textContent = "Ollama unavailable (rule-based fallback)";
        modelSelect.appendChild(option);
        modelSelect.disabled = true;
        modelStatus.textContent = "Could not reach local Ollama; planning will use the rule-based fallback.";
    }
}

async function pollStatus() {
    try {
        const res = await fetch(`${API_BASE}/assessment/status`);
        if (!res.ok) return;
        const data = await res.json();

        renderTimeline(data.runs);
        renderFindings(data.findings);

        if (data.pending_approvals && data.pending_approvals.length > 0) {
            triggerApprovalModal(data.pending_approvals[0]);
        }
    } catch (err) {
        console.error("Status polling error:", err);
    }
}

function renderTimeline(runs) {
    executionTimeline.innerHTML = "";
    if (!runs || runs.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "No live scans have been run. Import records below; imported outputs are not live execution.";
        executionTimeline.appendChild(empty);
        return;
    }
    runs.forEach(run => {
        const div = document.createElement("div");
        div.className = "timeline-item";
        const title = document.createElement("strong");
        title.textContent = `${run.tool_name} - ${run.status} (${run.mode || "mode not recorded"})`;
        const details = document.createElement("div");
        details.textContent = `${run.target} | ${run.rationale}`;
        div.append(title, details);
        executionTimeline.appendChild(div);
    });
}

function renderFindings(findings) {
    findingsBody.innerHTML = "";
    if (!findings || findings.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 8;
        cell.className = "empty-state";
        cell.textContent = "No findings loaded.";
        row.appendChild(cell);
        findingsBody.appendChild(row);
        return;
    }
    findings.forEach(f => {
        const tr = document.createElement("tr");
        [
            f.finding_id,
            f.severity,
            `${f.asset}:${f.port || "N/A"}`,
            f.source_tool,
            f.title,
            `${Math.round((f.confidence_level || 0) * 100)}%`,
            f.validation_status,
        ]
            .forEach((value, index) => {
                const cell = document.createElement("td");
                cell.textContent = value;
                if (index === 0) {
                    const code = document.createElement("code");
                    code.textContent = value;
                    cell.replaceChildren(code);
                }
                tr.appendChild(cell);
            });
        const evidenceCell = document.createElement("td");
        evidenceCell.className = "evidence-cell";
        const evidence = document.createElement("div");
        evidence.textContent = f.supporting_evidence || "No evidence text provided.";
        const reference = document.createElement("small");
        const sources = f.raw_reference?.sources || (f.raw_reference ? [f.raw_reference] : []);
        reference.textContent = sources.map(source => source.original_filename || source.file).join(", ") || "No source reference";
        evidenceCell.append(evidence, reference);
        tr.appendChild(evidenceCell);
        findingsBody.appendChild(tr);
    });
}

document.getElementById("evidenceForm").addEventListener("submit", async event => {
    event.preventDefault();
    const file = document.getElementById("evidenceFile").files[0];
    if (!file) return;
    planOutput.textContent = `Importing recorded ${document.getElementById("evidenceTool").value} output...`;
    try {
        const response = await fetch(`${API_BASE}/evidence/import`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                tool_name: document.getElementById("evidenceTool").value,
                target: document.getElementById("evidenceTarget").value.trim(),
                filename: file.name,
                content: await file.text(),
            }),
        });
        const result = await response.json();
        if (!response.ok) {
            planOutput.textContent = `Import rejected: ${result.detail || "Invalid import."}`;
            return;
        }
        planOutput.textContent = `Imported ${result.imported_findings} finding(s) from recorded ${result.tool_run.tool_name} output. No live scan was run.`;
        pollStatus();
    } catch (error) {
        planOutput.textContent = `Import failed: ${error.message}`;
    }
});

function triggerApprovalModal(request) {
    activeApprovalId = request.approval_id;
    modalDetails.innerHTML = `
        <p><strong>Tool:</strong> ${request.tool_name}</p>
        <p><strong>Target:</strong> ${request.target}</p>
        <p><strong>Proposed Action:</strong> ${request.proposed_action}</p>
        <p><strong>Risk Summary:</strong> ${request.risk_summary}</p>
    `;
    approvalModal.classList.remove("hidden");
}

async function resolveApproval(isApproved) {
    if (!activeApprovalId) return;
    const notes = analystNotes.value;

    await fetch(`${API_BASE}/approval/decide`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            approval_id: activeApprovalId,
            approved: isApproved,
            notes: notes
        })
    });

    approvalModal.classList.add("hidden");
    activeApprovalId = null;
    analystNotes.value = "";
    pollStatus();
}

document.getElementById("approveActionBtn").addEventListener("click", () => resolveApproval(true));
document.getElementById("rejectActionBtn").addEventListener("click", () => resolveApproval(false));

loadModels();

document.getElementById("generateReportBtn").addEventListener("click", async () => {
    const res = await fetch(`${API_BASE}/report/generate`, { method: "POST" });
    if (res.ok) alert("VAPT Report compiled successfully.");
});

document.getElementById("downloadReportBtn").addEventListener("click", () => {
    window.open(`${API_BASE}/report/download`, "_blank");
});