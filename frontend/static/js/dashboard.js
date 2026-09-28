/**
 * Security Operations Center (SOC) Dashboard Controller.
 * Handles telemetry metrics, Chart.js graphs, HITL approval queue, and audit logs.
 */

let latencyChart = null;

// Initialize Chart.js
function initDashboardCharts() {
  const canvas = document.getElementById('latency-chart-canvas');
  if (!canvas || typeof Chart === 'undefined') return;

  const ctx = canvas.getContext('2d');
  latencyChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Latency (ms)',
          data: [],
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56, 189, 248, 0.1)',
          fill: true,
          tension: 0.3,
          yAxisID: 'y'
        },
        {
          label: 'Tokens / Req',
          data: [],
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          fill: true,
          tension: 0.3,
          yAxisID: 'y1'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(51, 65, 85, 0.4)' },
          ticks: { color: '#94a3b8', font: { size: 10 } }
        },
        y: {
          type: 'linear',
          display: true,
          position: 'left',
          grid: { color: 'rgba(51, 65, 85, 0.4)' },
          ticks: { color: '#38bdf8', font: { size: 10 } }
        },
        y1: {
          type: 'linear',
          display: true,
          position: 'right',
          grid: { drawOnChartArea: false },
          ticks: { color: '#10b981', font: { size: 10 } }
        }
      },
      plugins: {
        legend: {
          labels: { color: '#e2e8f0', font: { size: 11 } }
        }
      }
    }
  });
}

// Refresh all dashboard metrics, charts, approvals, and logs
async function refreshDashboard() {
  await Promise.all([
    fetchMetrics(),
    fetchHITLQueue(),
    fetchAuditLogs()
  ]);
}

// Fetch Metrics Summary
async function fetchMetrics() {
  try {
    const res = await fetch('/api/security/metrics');
    const data = await res.json();
    State.metrics = data;

    // Update Counter Cards
    const elReqs = document.getElementById('stat-total-requests');
    const elBlocked = document.getElementById('stat-requests-blocked');
    const elAuth = document.getElementById('stat-auth-violations');
    const elTokens = document.getElementById('stat-tokens-consumed');
    const elLatency = document.getElementById('stat-avg-latency');
    const elBreaker = document.getElementById('stat-circuit-breaker');

    if (elReqs) elReqs.textContent = data.total_requests;
    if (elBlocked) elBlocked.textContent = data.requests_blocked;
    if (elAuth) elAuth.textContent = data.authorization_violations;
    if (elTokens) elTokens.textContent = data.total_tokens_consumed.toLocaleString();
    if (elLatency) elLatency.textContent = `${data.average_latency_ms} ms`;

    // Circuit Breaker Status
    if (elBreaker && data.circuit_breaker) {
      const state = data.circuit_breaker.state;
      elBreaker.textContent = state;
      if (state === 'OPEN') {
        elBreaker.className = 'font-mono font-bold text-red-400 animate-pulse';
      } else if (state === 'HALF_OPEN') {
        elBreaker.className = 'font-mono font-bold text-amber-400';
      } else {
        elBreaker.className = 'font-mono font-bold text-emerald-400';
      }
    }

    // Update Chart History
    if (latencyChart && data.history) {
      const labels = data.history.map(p => p.timestamp);
      const latencies = data.history.map(p => p.latency_ms);
      const tokens = data.history.map(p => p.tokens);

      latencyChart.data.labels = labels;
      latencyChart.data.datasets[0].data = latencies;
      latencyChart.data.datasets[1].data = tokens;
      latencyChart.update();
    }
  } catch (err) {
    console.error('Error fetching metrics', err);
  }
}

// Reset Metrics Counters
async function resetMetrics() {
  try {
    await fetch('/api/security/metrics/reset', { method: 'POST' });
    showToast('Telemetry metrics and quotas reset successfully.', 'success');
    refreshDashboard();
  } catch (err) {
    showToast('Failed to reset metrics', 'error');
  }
}

// Reset Circuit Breaker
async function resetCircuitBreaker() {
  try {
    await fetch('/api/security/circuit-breaker/reset', { method: 'POST' });
    showToast('Circuit breaker manually reset to CLOSED state.', 'success');
    refreshDashboard();
  } catch (err) {
    showToast('Failed to reset circuit breaker', 'error');
  }
}

// Toggle individual security control
async function handleToggleChange(toggleKey, isChecked) {
  const payload = {};
  payload[toggleKey] = isChecked;

  try {
    const res = await fetch('/api/security/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    State.config = data.config;
    updateConfigTogglesUI(data.config);
    showToast(`Security control '${toggleKey}' set to ${isChecked ? 'ENABLED' : 'DISABLED'}.`, 'info');
    if (window.fetchAvailableTools) window.fetchAvailableTools();
  } catch (err) {
    showToast('Failed to update security control.', 'error');
  }
}

// Fetch and render HITL Approval Queue
async function fetchHITLQueue() {
  try {
    const res = await fetch('/api/security/hitl/pending');
    const tickets = await res.json();
    State.pendingTickets = tickets;

    const countEl = document.getElementById('hitl-pending-count');
    if (countEl) countEl.textContent = tickets.length;

    const container = document.getElementById('hitl-tickets-container');
    if (!container) return;

    if (tickets.length === 0) {
      container.innerHTML = `
        <div class="p-6 text-center text-slate-500 text-xs italic">
          No sensitive operations currently pending supervisor approval.
        </div>
      `;
      return;
    }

    let html = '';
    for (const t of tickets) {
      html += `
        <div class="glass-panel p-4 rounded-lg border-l-4 border-amber-500 mb-3 text-xs">
          <div class="flex items-center justify-between mb-2">
            <div class="flex items-center space-x-2">
              <span class="font-mono font-bold text-amber-400">${t.ticket_id}</span>
              <span class="px-1.5 py-0.5 rounded text-[10px] font-bold badge-high">${t.risk_level} RISK</span>
            </div>
            <span class="text-slate-400 font-mono text-[11px]">${t.timestamp}</span>
          </div>

          <div class="text-slate-300 font-medium mb-1.5">
            Tool: <code class="bg-slate-900 px-1.5 py-0.5 rounded text-cyan-300 font-mono">${t.tool_name}</code>
            by <span class="text-sky-300 font-mono">${t.requested_by}</span> (${t.user_role})
          </div>

          <div class="text-slate-400 mb-2">
            <strong>Reason:</strong> ${escapeHtml(t.reason)}
          </div>

          <div class="bg-slate-900 p-2 rounded text-[11px] font-mono text-slate-300 mb-3 overflow-x-auto">
            ${escapeHtml(JSON.stringify(t.arguments, null, 2))}
          </div>

          <div class="flex items-center space-x-2 justify-end">
            <button onclick="rejectHITLTicket('${t.ticket_id}')" class="px-3 py-1.5 rounded bg-red-900/60 hover:bg-red-800 text-red-200 font-semibold text-xs border border-red-700 transition">
              ✕ Deny Operation
            </button>
            <button onclick="approveHITLTicket('${t.ticket_id}')" class="px-3 py-1.5 rounded bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 font-semibold text-xs border border-emerald-700 transition">
              ✓ Authorize & Execute
            </button>
          </div>
        </div>
      `;
    }
    container.innerHTML = html;
  } catch (err) {
    console.error('Error fetching HITL queue', err);
  }
}

// Approve HITL Ticket
async function approveHITLTicket(ticketId) {
  try {
    const res = await fetch('/api/security/hitl/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ticket_id: ticketId,
        reviewer: 'Supervisor_SOC_Admin',
        comment: 'Verified caller legitimacy and authorized operational exception.'
      })
    });
    const data = await res.json();
    if (res.ok) {
      showToast(`Ticket ${ticketId} approved and executed.`, 'success');
      refreshDashboard();
    } else {
      showToast(data.detail || 'Approval failed.', 'error');
    }
  } catch (err) {
    showToast('Failed to approve ticket.', 'error');
  }
}

// Reject HITL Ticket
async function rejectHITLTicket(ticketId) {
  try {
    const res = await fetch('/api/security/hitl/reject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ticket_id: ticketId,
        reviewer: 'Supervisor_SOC_Admin',
        comment: 'Denied due to excessive financial threshold or policy violation.'
      })
    });
    const data = await res.json();
    if (res.ok) {
      showToast(`Ticket ${ticketId} rejected and cancelled.`, 'info');
      refreshDashboard();
    } else {
      showToast(data.detail || 'Rejection failed.', 'error');
    }
  } catch (err) {
    showToast('Failed to reject ticket.', 'error');
  }
}

// Fetch and render Security Audit Log Feed
async function fetchAuditLogs() {
  const filterEl = document.getElementById('audit-filter-category');
  const category = filterEl ? filterEl.value : '';
  const url = category ? `/api/security/audit-logs?category=${encodeURIComponent(category)}` : '/api/security/audit-logs';

  try {
    const res = await fetch(url);
    const logs = await res.json();
    const container = document.getElementById('audit-logs-container');
    if (!container) return;

    if (logs.length === 0) {
      container.innerHTML = `
        <div class="p-6 text-center text-slate-500 text-xs italic">
          No security events recorded yet. Run a prompt or scenario to generate telemetry.
        </div>
      `;
      return;
    }

    let html = '';
    for (const log of logs) {
      const sevBadge =
        log.severity === 'CRITICAL' ? 'badge-critical' :
        log.severity === 'HIGH' ? 'badge-high' :
        log.severity === 'MEDIUM' ? 'badge-medium' :
        log.severity === 'INFO' ? 'badge-low' : 'badge-success';

      const decBadge =
        log.decision === 'ALLOWED' ? 'text-emerald-400' :
        log.decision === 'PENDING_APPROVAL' ? 'text-amber-400' :
        log.decision.startsWith('ALLOWED_BASELINE') ? 'text-red-400 font-bold' : 'text-red-400';

      html += `
        <div class="p-3 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition text-xs mb-2">
          <div class="flex items-center justify-between mb-1.5">
            <div class="flex items-center space-x-2">
              <span class="font-mono text-slate-400 text-[11px]">${log.timestamp}</span>
              <span class="font-bold text-sky-300 font-mono">${log.event_id}</span>
              <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${sevBadge}">${log.severity}</span>
            </div>
            <div class="font-mono text-[11px] ${decBadge}">${log.decision}</div>
          </div>

          <div class="flex items-center space-x-2 text-[11px] text-slate-400 mb-1">
            <span>User: <strong class="text-slate-200 font-mono">${log.user_id}</strong> (${log.user_role})</span>
            <span>•</span>
            <span>Action: <code class="text-cyan-300 font-mono">${log.action}</code></span>
            <span>•</span>
            <span class="text-purple-300">${log.risk_category}</span>
          </div>

          <div class="text-slate-300 mb-1">
            <strong>Impact:</strong> ${escapeHtml(log.impact_analysis)}
          </div>

          <div class="text-[11px] text-emerald-400/90 bg-slate-950/60 p-1.5 rounded font-mono">
            🛡️ <strong>Mitigation:</strong> ${escapeHtml(log.mitigation_applied)}
          </div>
        </div>
      `;
    }
    container.innerHTML = html;
  } catch (err) {
    console.error('Error fetching audit logs', err);
  }
}

// Clear Audit Logs
async function clearAuditLogs() {
  try {
    await fetch('/api/security/audit-logs/clear', { method: 'POST' });
    showToast('Security audit log stream cleared.', 'info');
    fetchAuditLogs();
  } catch (err) {
    showToast('Failed to clear audit logs.', 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initDashboardCharts();
});
