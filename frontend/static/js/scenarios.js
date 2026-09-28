/**
 * Interactive Presentation Flow & Demonstration Scenarios Controller.
 * Guided 6-Phase interactive walkthrough and comparative scenario execution.
 */

let scenariosCatalog = [];
let currentPhase = 1;
let activeScenarioId = 'scenario_excessive_agency_idor';

// Load Scenario Catalog
async function loadScenariosList() {
  try {
    const res = await fetch('/api/scenarios');
    scenariosCatalog = await res.json();
    renderScenariosGrid();
  } catch (err) {
    console.error('Failed to load scenarios catalog', err);
  }
}

// Render Scenario Cards Grid
function renderScenariosGrid() {
  const container = document.getElementById('scenarios-grid-container');
  if (!container) return;

  let html = '';
  for (const s of scenariosCatalog) {
    const isExcessive = s.category.includes('Excessive Agency');
    const badgeClass = isExcessive ? 'badge-high' : 'badge-medium';

    html += `
      <div class="glass-panel p-5 rounded-xl border border-slate-700/80 hover:border-sky-500/50 transition flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${s.category}</span>
            <span class="text-xs text-slate-400 font-mono">${s.user_id}</span>
          </div>

          <h3 class="text-sm font-bold text-slate-100 mb-1.5">${escapeHtml(s.title)}</h3>
          <p class="text-xs text-slate-400 leading-relaxed mb-3">${escapeHtml(s.description)}</p>

          <div class="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 text-[11px] font-mono text-cyan-300 mb-3 break-words">
            "${escapeHtml(s.query)}"
          </div>
        </div>

        <div class="pt-3 border-t border-slate-800 flex items-center justify-between">
          <button onclick="startPhaseTour('${s.id}')" class="text-xs text-purple-400 hover:text-purple-300 font-semibold flex items-center">
            <span>Guided 6-Phase Tour</span> →
          </button>
          <button onclick="runComparativeScenario('${s.id}')" class="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow transition">
            Run Side-by-Side Test
          </button>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

// Run automated comparative test (Baseline vs Mitigated side by side)
async function runComparativeScenario(scenarioId) {
  const modal = document.getElementById('comparison-modal');
  const content = document.getElementById('comparison-modal-content');
  if (!modal || !content) return;

  modal.classList.remove('hidden');
  content.innerHTML = `
    <div class="p-12 text-center text-slate-400">
      <div class="w-8 h-8 rounded-full border-2 border-sky-400 border-t-transparent animate-spin mx-auto mb-3"></div>
      <p class="text-sm font-medium">Executing Comparative Evaluation...</p>
      <p class="text-xs text-slate-500 mt-1">1. Executing vulnerable Baseline mode... 2. Executing hardened Mitigated mode...</p>
    </div>
  `;

  try {
    const res = await fetch('/api/scenarios/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario_id: scenarioId, compare_mode: true })
    });
    const data = await res.json();
    renderComparisonResults(data);
  } catch (err) {
    content.innerHTML = `<div class="p-6 text-center text-red-400">Execution failed: ${err.message}</div>`;
  }
}

// Render Side-by-Side Comparison Modal Content
function renderComparisonResults(data) {
  const content = document.getElementById('comparison-modal-content');
  const sc = data.scenario;
  const b = data.baseline_run;
  const m = data.mitigated_run;

  const bStatus = b.security_decision || 'ALLOWED_BASELINE_VULNERABLE';
  const mStatus = m.security_decision || 'BLOCKED / MITIGATED';

  // Format outputs
  const bResp = b.final_response || b.summary || JSON.stringify(b, null, 2);
  const mResp = m.final_response || m.summary || JSON.stringify(m, null, 2);

  const bTokens = b.telemetry ? b.telemetry.tokens_consumed : (b.total_tokens || 0);
  const mTokens = m.telemetry ? m.telemetry.tokens_consumed : (m.total_tokens || 0);

  const bLatency = b.telemetry ? `${b.telemetry.latency_ms} ms` : 'N/A';
  const mLatency = m.telemetry ? `${m.telemetry.latency_ms} ms` : 'N/A';

  content.innerHTML = `
    <div class="space-y-5">
      <div class="pb-3 border-b border-slate-700 flex items-center justify-between">
        <div>
          <span class="text-xs font-bold text-sky-400 uppercase tracking-wider">${sc.category}</span>
          <h2 class="text-lg font-bold text-slate-100">${escapeHtml(sc.title)}</h2>
        </div>
        <button onclick="document.getElementById('comparison-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
      </div>

      <div class="bg-slate-900/80 p-3 rounded-lg border border-slate-800 text-xs">
        <strong class="text-amber-400">Prompt / Payload:</strong>
        <div class="font-mono text-slate-300 mt-1">${escapeHtml(sc.query)}</div>
      </div>

      <!-- Side-by-side columns -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <!-- BASELINE RUN (Vulnerable) -->
        <div class="glass-panel p-4 rounded-xl border border-red-500/50 bg-red-950/10">
          <div class="flex items-center justify-between mb-3 pb-2 border-b border-red-900/60">
            <span class="text-xs font-bold text-red-400">🔴 BASELINE CONFIGURATION</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold badge-critical">${bStatus}</span>
          </div>

          <div class="text-xs text-slate-300 mb-2">
            <strong>Security Controls:</strong> <span class="text-red-300">Disabled (Unrestricted agency & consumption)</span>
          </div>

          <div class="bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-xs text-slate-200 mb-3 max-h-56 overflow-y-auto whitespace-pre-wrap font-mono">
${escapeHtml(bResp)}
          </div>

          <div class="grid grid-cols-2 gap-2 text-center text-xs">
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-[10px] text-slate-400">Tokens Burned</div>
              <div class="font-bold text-red-400 font-mono">${bTokens}</div>
            </div>
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-[10px] text-slate-400">Execution Latency</div>
              <div class="font-bold text-slate-200 font-mono">${bLatency}</div>
            </div>
          </div>

          <div class="mt-3 p-2.5 rounded bg-red-900/20 border border-red-700/40 text-xs text-red-300">
            ⚠️ <strong>Security Impact:</strong> ${escapeHtml(sc.baseline_expected)}
          </div>
        </div>

        <!-- MITIGATED RUN (Hardened) -->
        <div class="glass-panel p-4 rounded-xl border border-emerald-500/50 bg-emerald-950/10">
          <div class="flex items-center justify-between mb-3 pb-2 border-b border-emerald-900/60">
            <span class="text-xs font-bold text-emerald-400">🟢 MITIGATED CONFIGURATION</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold badge-success">${mStatus}</span>
          </div>

          <div class="text-xs text-slate-300 mb-2">
            <strong>Security Controls:</strong> <span class="text-emerald-300">Enabled (RBAC, Allowlists, Quotas, Breaker)</span>
          </div>

          <div class="bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-xs text-slate-200 mb-3 max-h-56 overflow-y-auto whitespace-pre-wrap font-mono">
${escapeHtml(mResp)}
          </div>

          <div class="grid grid-cols-2 gap-2 text-center text-xs">
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-[10px] text-slate-400">Tokens Burned</div>
              <div class="font-bold text-emerald-400 font-mono">${mTokens}</div>
            </div>
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-[10px] text-slate-400">Execution Latency</div>
              <div class="font-bold text-slate-200 font-mono">${mLatency}</div>
            </div>
          </div>

          <div class="mt-3 p-2.5 rounded bg-emerald-900/20 border border-emerald-700/40 text-xs text-emerald-300">
            🛡️ <strong>Defensive Protection:</strong> ${escapeHtml(sc.mitigated_expected)}
          </div>
        </div>
      </div>

      <!-- Educational Takeaway -->
      <div class="p-3.5 rounded-xl bg-purple-950/30 border border-purple-800/60 text-xs">
        <h4 class="font-bold text-purple-300 mb-1">Academic & Security Takeaway:</h4>
        <p class="text-slate-300 leading-relaxed mb-2">${escapeHtml(sc.risk_explanation)}</p>
        <div class="flex flex-wrap gap-1.5">
          ${data.educational_analysis.defense_mechanisms_proven.map(d => `<span class="px-2 py-0.5 rounded bg-purple-900/50 text-purple-200 text-[10px] border border-purple-700/50">${d}</span>`).join('')}
        </div>
      </div>
    </div>
  `;
}

// -------------------------------------------------------------
// GUIDED 6-PHASE INTERACTIVE PRESENTATION TOUR
// -------------------------------------------------------------
const PHASES = [
  {
    phase: 1,
    title: "Phase 1: Run Baseline Configuration",
    description: "Initialize the system in its vulnerable baseline state. All defensive security controls (RBAC, tool allowlists, rate limiters, token budgets, and circuit breakers) are turned OFF.",
    actionText: "Step 1: Set Vulnerable Baseline",
    action: async () => {
      await applyPreset('baseline');
      setPhase(2);
    }
  },
  {
    phase: 2,
    title: "Phase 2: Demonstrate Security Risk",
    description: "Launch the attack vector. An unauthorized user requests access to sensitive resources or attempts resource exhaustion.",
    actionText: "Step 2: Trigger Attack Scenario",
    action: async () => {
      const scenario = scenariosCatalog.find(s => s.id === activeScenarioId) || scenariosCatalog[0];
      switchTab('chat');
      injectPrompt(scenario.query);
      setPhase(3);
    }
  },
  {
    phase: 3,
    title: "Phase 3: Observe System Impact",
    description: "Examine the consequences of missing security controls: unauthorized PII exfiltrated, arbitrary funds debited, or high token consumption.",
    actionText: "Step 3: Review Security Impact",
    action: async () => {
      switchTab('dashboard');
      refreshDashboard();
      setPhase(4);
    }
  },
  {
    phase: 4,
    title: "Phase 4: Enable Security Controls",
    description: "Activate comprehensive defense-in-depth: RBAC, Least-Privilege Tool Allowlists, Human-in-the-Loop, Rate Limiters, Token Budgets, and Circuit Breakers.",
    actionText: "Step 4: Enable Hardened Controls",
    action: async () => {
      await applyPreset('hardened');
      setPhase(5);
    }
  },
  {
    phase: 5,
    title: "Phase 5: Repeat Scenario",
    description: "Repeat the exact same user request and attack vector under the hardened configuration posture.",
    actionText: "Step 5: Re-run Same Scenario",
    action: async () => {
      const scenario = scenariosCatalog.find(s => s.id === activeScenarioId) || scenariosCatalog[0];
      switchTab('chat');
      injectPrompt(scenario.query);
      setPhase(6);
    }
  },
  {
    phase: 6,
    title: "Phase 6: Demonstrate Successful Mitigation",
    description: "Verify that the defensive security controls successfully denied unauthorized access, enforced rate limits, created audit trails, and safeguarded system capacity.",
    actionText: "Step 6: Complete Tour & View Audit Logs",
    action: async () => {
      switchTab('dashboard');
      refreshDashboard();
      showToast('6-Phase Demonstration completed successfully!', 'success');
      setPhase(1);
    }
  }
];

function setPhase(phaseNum) {
  currentPhase = phaseNum;
  renderPhaseTourUI();
}

function startPhaseTour(scenarioId) {
  activeScenarioId = scenarioId;
  currentPhase = 1;
  renderPhaseTourUI();

  // Scroll to phase tour section
  const el = document.getElementById('phase-tour-section');
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function renderPhaseTourUI() {
  const container = document.getElementById('phase-tour-card');
  if (!container) return;

  const p = PHASES.find(x => x.phase === currentPhase);
  if (!p) return;

  const progressPct = ((currentPhase) / 6) * 100;

  container.innerHTML = `
    <div class="glass-panel p-6 rounded-xl border border-purple-500/40 bg-gradient-to-r from-purple-950/20 to-slate-900 shadow-xl">
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center space-x-2">
          <span class="w-7 h-7 rounded-full bg-purple-600 text-white font-bold flex items-center justify-center text-xs">
            ${p.phase}
          </span>
          <h3 class="text-base font-bold text-white">${p.title}</h3>
        </div>
        <span class="text-xs text-purple-300 font-mono">Phase ${p.phase} of 6</span>
      </div>

      <!-- Progress bar -->
      <div class="w-full bg-slate-800 rounded-full h-1.5 mb-4">
        <div class="bg-gradient-to-r from-purple-500 to-sky-400 h-1.5 rounded-full transition-all duration-500" style="width: ${progressPct}%"></div>
      </div>

      <p class="text-xs text-slate-300 leading-relaxed mb-4">${p.description}</p>

      <div class="flex items-center justify-between pt-3 border-t border-slate-800">
        <div class="text-xs text-slate-400">
          Target Scenario: <span class="text-sky-300 font-semibold font-mono">${activeScenarioId}</span>
        </div>
        <button onclick="PHASES[${currentPhase - 1}].action()" class="px-5 py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold shadow-lg transition flex items-center space-x-2">
          <span>${p.actionText}</span>
          <span>→</span>
        </button>
      </div>
    </div>
  `;
}

document.addEventListener('DOMContentLoaded', () => {
  renderPhaseTourUI();
});
