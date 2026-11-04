/**
 * frontend/app.js
 * Client logic coordinating API requests, status polling, and approvals.
 */

const API_BASE = "http://localhost:8000/api";
let activeApprovalId = null;

const assessmentForm = document.getElementById("assessmentForm");
const planOutput = document.getElementById("planOutput");
const executionTimeline = document.getElementById("executionTimeline");
const findingsBody = document.getElementById("findingsBody");
const approvalModal = document.getElementById("approvalModal");
const modalDetails = document.getElementById("modalDetails");
const analystNotes = document.getElementById("analystNotes");

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
                excluded_targets: exclusions
            })
        });

        if (!res.ok) {
            const err = await res.json();
            planOutput.textContent = `Error: ${err.detail || "Unable to start assessment."}`;
            return;
        }

        const data = await res.json();
        renderPlan(data.plan);
        pollStatus();
    } catch (err) {
        planOutput.textContent = `Network failure: ${err.message}`;
    }
});

function renderPlan(plan) {
    let output = "=== APPROVED ASSESSMENT PLAN ===\n";
    plan.forEach(step => {
        output += `Stage ${step.stage}: [${step.tool}] on target ${step.target}\nRationale: ${step.rationale}\n\n`;
    });
    planOutput.textContent = output;
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
    if (!runs || runs.length === 0) return;
    executionTimeline.innerHTML = "";
    runs.forEach(run => {
        const div = document.createElement("div");
        div.className = "timeline-item";
        div.innerHTML = `<strong>${run.tool_name}</strong> - ${run.status} (${run.target})<br><small>${run.rationale}</small>`;
        executionTimeline.appendChild(div);
    });
}

function renderFindings(findings) {
    if (!findings || findings.length === 0) return;
    findingsBody.innerHTML = "";
    findings.forEach(f => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><code>${f.finding_id}</code></td>
            <td><strong>${f.severity}</strong></td>
            <td>${f.asset}:${f.port || "N/A"}</td>
            <td>${f.source_tool}</td>
            <td>${f.title}</td>
        `;
        findingsBody.appendChild(tr);
    });
}

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

document.getElementById("generateReportBtn").addEventListener("click", async () => {
    const res = await fetch(`${API_BASE}/report/generate`, { method: "POST" });
    if (res.ok) alert("VAPT Report compiled successfully.");
});

document.getElementById("downloadReportBtn").addEventListener("click", () => {
    window.open(`${API_BASE}/report/download`, "_blank");
});