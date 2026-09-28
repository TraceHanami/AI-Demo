/**
 * Chat Interface and ReAct Reasoning Inspector.
 */

let lastTraceData = null;

// Send Message from input
async function sendChatMessage() {
  const inputEl = document.getElementById('chat-input');
  const query = inputEl.value.trim();
  if (!query) return;

  inputEl.value = '';
  appendUserMessage(query);

  // Show loading indicator
  const loadingId = appendLoadingMessage();

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: query,
        user_id: State.userId,
        user_role: State.userRole,
        session_id: State.sessionId
      })
    });

    const trace = await res.json();
    removeLoadingMessage(loadingId);

    // Save and render trace
    lastTraceData = trace;
    appendAssistantMessage(trace);
    renderTraceInspector(trace);

    // Update exposed tools
    fetchAvailableTools();

  } catch (err) {
    removeLoadingMessage(loadingId);
    appendSystemMessage(`Error processing request: ${err.message}`, 'error');
  }
}

// Quick action buttons
function injectPrompt(promptText) {
  const inputEl = document.getElementById('chat-input');
  inputEl.value = promptText;
  sendChatMessage();
}

// Render User Message
function appendUserMessage(text) {
  const container = document.getElementById('chat-messages-container');
  const msgDiv = document.createElement('div');
  msgDiv.className = 'flex justify-end mb-4';
  msgDiv.innerHTML = `
    <div class="max-w-xl rounded-2xl px-5 py-3.5 chat-bubble-user shadow-md">
      <div class="flex items-center space-x-2 text-xs text-blue-200 mb-1">
        <span class="font-bold">${State.userId}</span>
        <span>•</span>
        <span class="capitalize">${State.userRole}</span>
      </div>
      <div class="text-sm whitespace-pre-wrap">${escapeHtml(text)}</div>
    </div>
  `;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

// Render Assistant Message
function appendAssistantMessage(trace) {
  const container = document.getElementById('chat-messages-container');
  const msgDiv = document.createElement('div');
  msgDiv.className = 'flex justify-start mb-4';

  const decision = trace.security_decision;
  let statusBadge = '';
  if (decision === 'ALLOWED') {
    statusBadge = '<span class="px-2 py-0.5 text-xs font-semibold rounded badge-success">✓ ALLOWED</span>';
  } else if (decision === 'PENDING_APPROVAL') {
    statusBadge = '<span class="px-2 py-0.5 text-xs font-semibold rounded badge-high">⏳ HITL APPROVAL REQUIRED</span>';
  } else if (decision === 'RATE_LIMITED' || decision === 'CIRCUIT_BROKEN') {
    statusBadge = '<span class="px-2 py-0.5 text-xs font-semibold rounded badge-critical">⚠️ RATE LIMITED</span>';
  } else {
    statusBadge = '<span class="px-2 py-0.5 text-xs font-semibold rounded badge-critical">🚫 ACCESS BLOCKED</span>';
  }

  // Format markdown-like bold/code blocks simply
  let formattedResp = escapeHtml(trace.final_response)
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="bg-slate-800 px-1.5 py-0.5 rounded text-cyan-300 font-mono text-xs">$1</code>')
    .replace(/```([\s\S]*?)```/g, '<pre class="bg-slate-900 p-2.5 rounded text-xs font-mono overflow-x-auto text-emerald-400 mt-2">$1</pre>');

  msgDiv.innerHTML = `
    <div class="max-w-2xl rounded-2xl px-5 py-4 chat-bubble-assistant shadow-md border border-slate-700">
      <div class="flex items-center justify-between text-xs text-slate-400 mb-2 border-b border-slate-700/60 pb-2">
        <div class="flex items-center space-x-2">
          <span class="font-bold text-sky-400">🤖 AI Support Assistant</span>
          <span>•</span>
          <span>${trace.request_id}</span>
        </div>
        <div class="flex items-center space-x-2">
          ${statusBadge}
          <button onclick='renderTraceInspector(lastTraceData)' class="text-xs text-cyan-400 hover:text-cyan-300 underline font-medium">Inspect Trace</button>
        </div>
      </div>
      <div class="text-sm whitespace-pre-wrap text-slate-200 leading-relaxed">${formattedResp}</div>
      <div class="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
        <div>Latency: <span class="text-slate-300">${trace.telemetry.latency_ms} ms</span> | Tokens: <span class="text-slate-300">${trace.telemetry.tokens_consumed}</span></div>
        <div>Circuit: <span class="text-slate-300 font-mono">${trace.telemetry.circuit_state || 'CLOSED'}</span></div>
      </div>
    </div>
  `;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

// Loading indicator
function appendLoadingMessage() {
  const container = document.getElementById('chat-messages-container');
  const id = 'loading-' + Date.now();
  const div = document.createElement('div');
  div.id = id;
  div.className = 'flex justify-start mb-4';
  div.innerHTML = `
    <div class="rounded-2xl px-5 py-3 chat-bubble-assistant text-slate-400 text-xs flex items-center space-x-2">
      <div class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></div>
      <span>ReAct Agent is reasoning and evaluating security policies...</span>
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeLoadingMessage(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function appendSystemMessage(text, type = 'info') {
  const container = document.getElementById('chat-messages-container');
  const div = document.createElement('div');
  div.className = 'flex justify-center mb-4';
  div.innerHTML = `<div class="rounded-lg px-4 py-2 text-xs chat-bubble-system">${escapeHtml(text)}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// ReAct Trace Inspector Renderer
function renderTraceInspector(trace) {
  if (!trace) return;
  const container = document.getElementById('trace-inspector-content');
  if (!container) return;

  const decisionBadgeClass =
    trace.security_decision === 'ALLOWED' ? 'badge-success' :
    trace.security_decision === 'PENDING_APPROVAL' ? 'badge-high' : 'badge-critical';

  let thoughtsHtml = trace.thought_process.map(t => `<div class="mb-1 text-slate-300 font-mono text-xs">• ${escapeHtml(t)}</div>`).join('');
  let toolArgsHtml = trace.tool_arguments ? `<pre class="bg-slate-900 p-2 rounded text-xs text-amber-300 font-mono">${escapeHtml(JSON.stringify(trace.tool_arguments, null, 2))}</pre>` : '<span class="text-slate-500 italic text-xs">None</span>';
  let toolOutputHtml = trace.tool_output ? `<pre class="bg-slate-900 p-2 rounded text-xs text-emerald-300 font-mono overflow-x-auto max-h-48">${escapeHtml(JSON.stringify(trace.tool_output, null, 2))}</pre>` : '<span class="text-slate-500 italic text-xs">None</span>';

  let secDetailsHtml = '<span class="text-slate-400 text-xs">No violation detected.</span>';
  if (trace.security_details) {
    secDetailsHtml = `
      <div class="text-xs space-y-1">
        <div><strong class="text-red-400">Policy:</strong> ${escapeHtml(trace.security_details.policy || '')}</div>
        <div><strong class="text-amber-400">Reason:</strong> ${escapeHtml(trace.security_details.reason || '')}</div>
        <div><strong class="text-sky-400">OWASP Mapping:</strong> ${escapeHtml(trace.security_details.owasp_mapping || '')}</div>
      </div>
    `;
  }

  container.innerHTML = `
    <div class="space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-slate-700">
        <div>
          <span class="text-xs text-slate-400 uppercase tracking-wider font-semibold">Request ID:</span>
          <span class="text-xs font-mono text-sky-400 ml-1 font-bold">${trace.request_id}</span>
        </div>
        <div>
          <span class="px-2.5 py-1 rounded text-xs font-bold ${decisionBadgeClass}">${trace.security_decision}</span>
        </div>
      </div>

      <!-- Step 1: User Request -->
      <div class="glass-panel p-3 rounded-lg">
        <div class="text-xs font-semibold text-sky-400 mb-1 flex items-center">
          <span class="w-4 h-4 rounded-full bg-sky-500/20 text-sky-300 inline-flex items-center justify-center text-[10px] mr-1.5">1</span>
          User Input & Identity
        </div>
        <div class="text-xs text-slate-200 font-medium">${escapeHtml(trace.query)}</div>
        <div class="text-[11px] text-slate-400 mt-1">Caller: <span class="text-cyan-300 font-mono">${trace.session_user_id}</span> | Role: <span class="text-amber-300 font-mono">${trace.user_role}</span></div>
      </div>

      <!-- Step 2: Agent Thought Process -->
      <div class="glass-panel p-3 rounded-lg">
        <div class="text-xs font-semibold text-purple-400 mb-1 flex items-center">
          <span class="w-4 h-4 rounded-full bg-purple-500/20 text-purple-300 inline-flex items-center justify-center text-[10px] mr-1.5">2</span>
          ReAct Agent Thought Process
        </div>
        ${thoughtsHtml}
      </div>

      <!-- Step 3: Tool Invocation & Params -->
      <div class="glass-panel p-3 rounded-lg">
        <div class="text-xs font-semibold text-amber-400 mb-1 flex items-center">
          <span class="w-4 h-4 rounded-full bg-amber-500/20 text-amber-300 inline-flex items-center justify-center text-[10px] mr-1.5">3</span>
          Tool Selected & Arguments
        </div>
        <div class="text-xs font-mono text-amber-200 mb-1.5 font-bold">
          Tool: ${trace.tool_called ? `<span class="bg-amber-950/60 text-amber-300 px-2 py-0.5 rounded border border-amber-800">${trace.tool_called}</span>` : '<span class="text-slate-500">Direct response (No tool)</span>'}
        </div>
        ${toolArgsHtml}
      </div>

      <!-- Step 4: Security Evaluation Intercept -->
      <div class="glass-panel p-3 rounded-lg border-l-4 ${trace.security_decision === 'ALLOWED' ? 'border-emerald-500' : 'border-red-500'}">
        <div class="text-xs font-semibold text-cyan-400 mb-1 flex items-center">
          <span class="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-300 inline-flex items-center justify-center text-[10px] mr-1.5">4</span>
          Defensive Security Evaluation Intercept
        </div>
        ${secDetailsHtml}
      </div>

      <!-- Step 5: Tool Execution Observation -->
      <div class="glass-panel p-3 rounded-lg">
        <div class="text-xs font-semibold text-emerald-400 mb-1 flex items-center">
          <span class="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-300 inline-flex items-center justify-center text-[10px] mr-1.5">5</span>
          Tool Observation / Execution Result
        </div>
        ${toolOutputHtml}
      </div>

      <!-- Step 6: Telemetry -->
      <div class="glass-panel p-3 rounded-lg bg-slate-900/60">
        <div class="text-xs font-semibold text-slate-400 mb-1">Execution Telemetry</div>
        <div class="grid grid-cols-3 gap-2 text-center text-xs">
          <div class="p-2 rounded bg-slate-800/80">
            <div class="text-slate-400 text-[10px]">Latency</div>
            <div class="font-bold text-sky-400 font-mono">${trace.telemetry.latency_ms} ms</div>
          </div>
          <div class="p-2 rounded bg-slate-800/80">
            <div class="text-slate-400 text-[10px]">Tokens</div>
            <div class="font-bold text-emerald-400 font-mono">${trace.telemetry.tokens_consumed}</div>
          </div>
          <div class="p-2 rounded bg-slate-800/80">
            <div class="text-slate-400 text-[10px]">Circuit State</div>
            <div class="font-bold text-amber-400 font-mono">${trace.telemetry.circuit_state || 'CLOSED'}</div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Fetch currently exposed tools based on active security posture
async function fetchAvailableTools() {
  try {
    const res = await fetch(`/api/tools?user_role=${State.userRole}`);
    const data = await res.json();
    const container = document.getElementById('exposed-tools-list');
    if (!container) return;

    let html = '';
    for (const [toolName, toolMeta] of Object.entries(data.tools)) {
      const riskBadge =
        toolMeta.risk_level === 'CRITICAL' ? 'badge-critical' :
        toolMeta.risk_level === 'HIGH' ? 'badge-high' :
        toolMeta.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low';

      html += `
        <div class="p-2.5 rounded-lg bg-slate-800/70 border border-slate-700/60 text-xs hover:border-slate-600 transition">
          <div class="flex items-center justify-between mb-1">
            <span class="font-mono font-bold text-sky-300">${toolName}</span>
            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${riskBadge}">${toolMeta.risk_level}</span>
          </div>
          <div class="text-slate-400 text-[11px] line-clamp-2">${toolMeta.description}</div>
          <div class="text-[10px] text-slate-500 mt-1">Min Role: <span class="text-slate-300 font-mono">${toolMeta.minimum_role}</span></div>
        </div>
      `;
    }
    container.innerHTML = html;
  } catch (err) {
    console.error('Error fetching available tools', err);
  }
}

function clearChatMessages() {
  const container = document.getElementById('chat-messages-container');
  container.innerHTML = '';
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

document.addEventListener('DOMContentLoaded', () => {
  const chatInput = document.getElementById('chat-input');
  if (chatInput) {
    chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage();
      }
    });
  }
  fetchAvailableTools();
});
