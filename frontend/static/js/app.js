/**
 * Global Application Controller
 * Manages tabs, user session/role, and periodic status synchronization.
 */

const State = {
  currentTab: 'chat',
  userId: 'CUST-1001',
  userRole: 'customer',
  sessionId: 'session_' + Math.random().toString(36).substring(2, 9),
  config: {},
  metrics: {},
  pendingTickets: []
};

// Switch active tab
function switchTab(tabName) {
  State.currentTab = tabName;
  document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

  const targetTab = document.getElementById(`tab-${tabName}`);
  const targetBtn = document.getElementById(`btn-tab-${tabName}`);

  if (targetTab) targetTab.classList.remove('hidden');
  if (targetBtn) targetBtn.classList.add('active');

  if (tabName === 'dashboard') {
    refreshDashboard();
  } else if (tabName === 'scenarios') {
    loadScenariosList();
  }
}

// User Persona Selector
function setPersona(userId, role, label) {
  State.userId = userId;
  State.userRole = role;
  document.getElementById('current-persona-label').textContent = `${label} (${userId} - ${role})`;

  // Update badge color
  const badge = document.getElementById('current-persona-badge');
  if (badge) {
    if (role === 'admin') badge.className = 'px-2 py-0.5 text-xs font-semibold rounded badge-critical';
    else if (role.startsWith('support')) badge.className = 'px-2 py-0.5 text-xs font-semibold rounded badge-high';
    else badge.className = 'px-2 py-0.5 text-xs font-semibold rounded badge-medium';
  }

  // Reload tool registry view
  if (window.fetchAvailableTools) window.fetchAvailableTools();
}

// Fetch security configuration
async function fetchSecurityConfig() {
  try {
    const res = await fetch('/api/security/config');
    const data = await res.json();
    State.config = data;
    updateConfigTogglesUI(data);
  } catch (err) {
    console.error('Failed to load security config', err);
  }
}

// Update config toggle switches in UI
function updateConfigTogglesUI(config) {
  const toggleMap = {
    'toggle-rbac': config.rbac_enabled,
    'toggle-allowlist': config.tool_allowlist_enabled,
    'toggle-ownership': config.parameter_validation_enabled,
    'toggle-hitl': config.hitl_enabled,
    'toggle-rag-acl': config.rag_acl_enabled,
    'toggle-rate-limit': config.rate_limiting_enabled,
    'toggle-quota': config.request_quota_enabled,
    'toggle-tokens': config.token_budgeting_enabled,
    'toggle-timeout': config.timeout_control_enabled,
    'toggle-circuit-breaker': config.circuit_breaker_enabled
  };

  for (const [id, val] of Object.entries(toggleMap)) {
    const el = document.getElementById(id);
    if (el) el.checked = !!val;
  }

  // Update posture banner
  const isHardened = Object.values(config).filter(v => v === true).length >= 5;
  const postureEl = document.getElementById('security-posture-badge');
  if (postureEl) {
    if (isHardened) {
      postureEl.textContent = '🛡️ HARDENED DEFENSE ACTIVE';
      postureEl.className = 'px-3 py-1 rounded-full text-xs font-bold badge-success shadow';
    } else {
      postureEl.textContent = '⚠️ VULNERABLE BASELINE ACTIVE';
      postureEl.className = 'px-3 py-1 rounded-full text-xs font-bold badge-critical animate-pulse-slow shadow';
    }
  }

  // Update AI Engine Indicator
  updateEngineBadgeUI(config);
}

// Update Model Engine Badge in Navbar
function updateEngineBadgeUI(config) {
  const iconEl = document.getElementById('model-engine-icon');
  const labelEl = document.getElementById('model-engine-label');
  const btnEl = document.getElementById('btn-model-engine');
  if (!iconEl || !labelEl) return;

  const provider = config.llm_provider || 'deterministic';
  if (provider === 'gemini') {
    iconEl.textContent = '✨';
    labelEl.textContent = `Live Gemini (${config.llm_model_name || 'gemini-1.5-flash'})`;
    if (btnEl) btnEl.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-purple-950/80 hover:bg-purple-900 border border-purple-700 text-purple-200 font-semibold transition shadow';
  } else if (provider === 'openai') {
    iconEl.textContent = '🌐';
    labelEl.textContent = `Live OpenAI (${config.llm_model_name || 'gpt-4o-mini'})`;
    if (btnEl) btnEl.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 font-semibold transition shadow';
  } else if (provider === 'ollama') {
    iconEl.textContent = '🦙';
    labelEl.textContent = `Local Ollama (${config.llm_model_name || 'llama3'})`;
    if (btnEl) btnEl.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-700 text-amber-200 font-semibold transition shadow';
  } else {
    iconEl.textContent = '🧠';
    labelEl.textContent = 'Sample Data (Academic Engine)';
    if (btnEl) btnEl.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sky-300 font-semibold transition shadow';
  }
}

// Model Settings Modal Open / Close
function openModelSettingsModal() {
  const modal = document.getElementById('model-settings-modal');
  if (!modal) return;

  const p = State.config.llm_provider || 'deterministic';
  const radios = document.getElementsByName('llm_provider_choice');
  for (const r of radios) {
    if (r.value === p) r.checked = true;
  }

  const keyEl = document.getElementById('cfg-llm-api-key');
  const modelEl = document.getElementById('cfg-llm-model-name');
  const urlEl = document.getElementById('cfg-llm-base-url');

  if (keyEl) keyEl.value = State.config.llm_api_key || '';
  if (modelEl) modelEl.value = State.config.llm_model_name || '';
  if (urlEl) urlEl.value = State.config.llm_base_url || '';

  toggleProviderInputs(p);
  modal.classList.remove('hidden');
}

function closeModelSettingsModal() {
  const modal = document.getElementById('model-settings-modal');
  if (modal) modal.classList.add('hidden');
}

function toggleProviderInputs(provider) {
  const liveFields = document.getElementById('live-model-fields');
  const urlEl = document.getElementById('cfg-llm-base-url');
  const modelEl = document.getElementById('cfg-llm-model-name');

  if (provider === 'deterministic') {
    if (liveFields) liveFields.classList.add('opacity-40', 'pointer-events-none');
  } else {
    if (liveFields) liveFields.classList.remove('opacity-40', 'pointer-events-none');
    if (provider === 'ollama') {
      if (urlEl && !urlEl.value) urlEl.value = 'http://localhost:11434/v1';
      if (modelEl && !modelEl.value) modelEl.value = 'llama3';
    } else if (provider === 'gemini') {
      if (modelEl && !modelEl.value) modelEl.value = 'gemini-1.5-flash';
    } else if (provider === 'openai') {
      if (modelEl && !modelEl.value) modelEl.value = 'gpt-4o-mini';
    }
  }
}

// Save Model Settings
async function saveModelSettings() {
  let selectedProvider = 'deterministic';
  const radios = document.getElementsByName('llm_provider_choice');
  for (const r of radios) {
    if (r.checked) selectedProvider = r.value;
  }

  const key = document.getElementById('cfg-llm-api-key')?.value.trim() || '';
  const model = document.getElementById('cfg-llm-model-name')?.value.trim() || '';
  const url = document.getElementById('cfg-llm-base-url')?.value.trim() || '';

  const payload = {
    llm_provider: selectedProvider,
    llm_api_key: key,
    llm_model_name: model,
    llm_base_url: url
  };

  try {
    const res = await fetch('/api/security/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    State.config = data.config;
    updateConfigTogglesUI(data.config);
    closeModelSettingsModal();
    showToast(`AI Engine updated to: ${selectedProvider.toUpperCase()}`, 'success');
  } catch (err) {
    showToast('Failed to update AI Engine configuration.', 'error');
  }
}

// Reset to Deterministic Sample Engine
async function resetToDeterministicEngine() {
  try {
    const res = await fetch('/api/security/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ llm_provider: 'deterministic' })
    });
    const data = await res.json();
    State.config = data.config;
    updateConfigTogglesUI(data.config);
    closeModelSettingsModal();
    showToast('AI Engine reset to Academic Simulator (Sample Data).', 'info');
  } catch (err) {
    showToast('Failed to reset AI Engine.', 'error');
  }
}

// Apply Preset Profile
async function applyPreset(mode) {
  const endpoint = mode === 'baseline' ? '/api/security/preset/baseline' : '/api/security/preset/hardened';
  try {
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    State.config = data.config;
    updateConfigTogglesUI(data.config);
    showToast(`Applied ${data.preset} profile.`, 'info');
    refreshDashboard();
    if (window.fetchAvailableTools) window.fetchAvailableTools();
  } catch (err) {
    showToast('Failed to apply security preset.', 'error');
  }
}

// Simple Toast Notification
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const borderCol = type === 'error' ? 'border-red-500' : type === 'success' ? 'border-green-500' : 'border-blue-500';
  toast.className = `glass-panel px-4 py-3 rounded shadow-lg text-sm text-white border-l-4 ${borderCol} mb-2 transition-all duration-300 transform translate-y-0 opacity-100 flex items-center justify-between`;
  toast.innerHTML = `<span>${message}</span><button class="ml-3 text-slate-400 hover:text-white" onclick="this.parentElement.remove()">✕</button>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Initialization on DOM load
document.addEventListener('DOMContentLoaded', () => {
  fetchSecurityConfig();
  switchTab('chat');

  // Periodic polling for metrics & approvals
  setInterval(() => {
    if (State.currentTab === 'dashboard') {
      refreshDashboard();
    }
  }, 3000);
});
