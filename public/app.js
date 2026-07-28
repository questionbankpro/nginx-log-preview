let statusChartInstance = null;
let botChartInstance = null;

let currentPage = 1;
let currentLimit = 50;

// Global State loaded from localStorage
let globalStartDate = localStorage.getItem('nginx_start_date') || '';
let globalEndDate = localStorage.getItem('nginx_end_date') || '';
let globalStatuses = JSON.parse(localStorage.getItem('nginx_statuses') || '["2xx","3xx","403","404","5xx"]');

function getGlobalDateQueryParams() {
  const params = new URLSearchParams();
  if (globalStartDate) params.append('startDate', globalStartDate.replace('T', ' '));
  if (globalEndDate) params.append('endDate', globalEndDate.replace('T', ' '));
  if (globalStatuses && globalStatuses.length > 0) params.append('statuses', globalStatuses.join(','));
  return params.toString();
}

function getSelectedCheckboxes() {
  const cbs = document.querySelectorAll('.status-cb:checked');
  return Array.from(cbs).map(cb => cb.value);
}


let auditCurrentPage = 1;
let currentAuditedIp = '';

async function loadPartials() {
  try {
    const [sidebarRes, filterRes, metricsRes] = await Promise.all([
      fetch('/partials/sidebar.html'),
      fetch('/partials/filter-bar.html'),
      fetch('/partials/metrics-header.html')
    ]);

    document.getElementById('partial-sidebar').outerHTML = await sidebarRes.text();
    document.getElementById('partial-filter-bar').outerHTML = await filterRes.text();
    document.getElementById('partial-metrics-header').outerHTML = await metricsRes.text();
  } catch (err) {
    console.error('Error loading partials', err);
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadPartials();

  setupTabNavigation();
  setupGlobalDateFilter();
  setupTableSorting();

  // Collapsible Sidebar Handler (Desktop & Mobile)
  const sidebar = document.querySelector('.sidebar');

  const toggleBtn = document.getElementById('btn-toggle-sidebar');
  const isCollapsed = localStorage.getItem('sidebar_collapsed') === 'true';


  if (isCollapsed && sidebar) {
    sidebar.classList.add('collapsed');
  }

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
      localStorage.setItem('sidebar_collapsed', sidebar.classList.contains('collapsed'));
    });
  }

  refreshAllData();


  // IP Audit Event Handlers
  const auditBtn = document.getElementById('btn-ip-audit-search');
  if (auditBtn) {
    auditBtn.addEventListener('click', () => {
      currentAuditedIp = document.getElementById('ip-audit-input').value.trim();
      auditCurrentPage = 1;
      if (currentAuditedIp) performIpAudit(currentAuditedIp);
    });
  }

  document.getElementById('audit-prev-page').addEventListener('click', () => {
    if (auditCurrentPage > 1) {
      auditCurrentPage--;
      performIpAudit(currentAuditedIp);
    }
  });

  document.getElementById('audit-next-page').addEventListener('click', () => {
    auditCurrentPage++;
    performIpAudit(currentAuditedIp);
  });

  document.getElementById('audit-logs-limit').addEventListener('change', () => {
    auditCurrentPage = 1;
    performIpAudit(currentAuditedIp);
  });

  let auditSearchTimeout;
  document.getElementById('audit-logs-search').addEventListener('input', () => {
    clearTimeout(auditSearchTimeout);
    auditSearchTimeout = setTimeout(() => {
      auditCurrentPage = 1;
      performIpAudit(currentAuditedIp);
    }, 300);
  });

  // Search Listeners
  document.getElementById('btn-search').addEventListener('click', () => {
    currentPage = 1;
    loadLogs();
  });



  document.getElementById('btn-reset').addEventListener('click', () => {
    document.getElementById('search-query').value = '';
    document.getElementById('status-filter').value = '';
    document.getElementById('type-filter').value = '';
    currentPage = 1;
    loadLogs();
  });

  document.getElementById('prev-page').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      loadLogs();
    }
  });

  document.getElementById('next-page').addEventListener('click', () => {
    currentPage++;
    loadLogs();
  });

  document.getElementById('ip-filter-input').addEventListener('input', (e) => {
    const val = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('#ip-table-body tr');
    rows.forEach(r => {
      r.style.display = r.innerText.toLowerCase().includes(val) ? '' : 'none';
    });
  });
});


async function performIpAudit(ip) {
  try {
    currentAuditedIp = ip;
    const limit = document.getElementById('audit-logs-limit').value || 100;
    const search = document.getElementById('audit-logs-search').value.trim();
    const dateParams = getGlobalDateQueryParams();

    const url = `/api/ip-audit?ip=${encodeURIComponent(ip)}&page=${auditCurrentPage}&limit=${limit}&search=${encodeURIComponent(search)}&${dateParams}`;
    const res = await fetch(url);
    const data = await res.json();

    document.getElementById('ip-audit-results').style.display = 'flex';
    document.getElementById('audit-ip-val').innerText = data.searched_ip;
    document.getElementById('audit-count-val').innerText = data.matched_logs_count.toLocaleString();
    document.getElementById('audit-bot-val').innerText = (data.bot_categories || []).join(', ') || 'Unknown';
    document.getElementById('audit-ua-val').innerText = (data.user_agents || []).join('\n') || 'None';

    const statusContainer = document.getElementById('audit-status-counts');
    statusContainer.innerHTML = '';
    Object.keys(data.status_summary || {}).forEach(st => {
      const badge = document.createElement('span');
      badge.className = `badge ${st >= 400 ? 'badge-danger' : 'badge-success'}`;
      badge.innerText = `HTTP ${st}: ${data.status_summary[st]}`;
      statusContainer.appendChild(badge);
    });

    const pathsBody = document.getElementById('audit-paths-body');
    pathsBody.innerHTML = '';
    (data.top_paths || []).forEach(p => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><strong>${p.count}</strong></td><td><code>${escapeHtml(p.path)}</code></td>`;
      pathsBody.appendChild(tr);
    });

    const rawBody = document.getElementById('audit-raw-body');
    rawBody.innerHTML = '';
    (data.logs || []).forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="white-space: nowrap;">${r.timestamp}</td>
        <td><strong>${r.method}</strong></td>
        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(r.path)}"><code>${escapeHtml(r.path)}</code></td>
        <td><span class="badge ${r.status >= 400 ? 'badge-danger' : 'badge-success'}">${r.status}</span></td>
        <td><span class="badge badge-info">${r.source_file || 'log'}</span></td>
      `;
      rawBody.appendChild(tr);
    });

    // Update Pagination Bar
    document.getElementById('audit-page-indicator').innerText = `Page ${data.pagination.page} of ${data.pagination.totalPages}`;
    document.getElementById('audit-prev-page').disabled = data.pagination.page <= 1;
    document.getElementById('audit-next-page').disabled = data.pagination.page >= data.pagination.totalPages;

  } catch (err) {
    console.error('Error performing IP audit', err);
  }
}



function refreshAllData() {
  fetchSummary();
  loadOverviewCharts();
  loadBotsTab();
  loadGooglebotTab();
  loadSecurityTab();
  loadIPAnalytics();
  loadStatusMatrixTab();
  loadAccessDeniedTab();
  loadLogs();
}

async function loadSecurityTab() {
  try {
    const q = getGlobalDateQueryParams();
    const [threatRes, rulesRes] = await Promise.all([
      fetch(`/api/security/threats?${q}`),
      fetch(`/api/security/rules-generator?${q}`)
    ]);

    const threatData = await threatRes.json();
    const rulesData = await rulesRes.json();

    const catContainer = document.getElementById('threat-categories-list');
    catContainer.innerHTML = '';
    (threatData.threat_categories || []).forEach(tc => {
      const item = document.createElement('div');
      item.className = 'd-flex justify-content-between align-items-center p-2 rounded bg-dark border border-secondary-subtle';
      item.innerHTML = `
        <span><strong>${tc.name}</strong> (${tc.unique_ips_count} IPs)</span>
        <span class="badge bg-danger">${tc.count} Hits</span>
      `;
      catContainer.appendChild(item);
    });

    document.getElementById('snippet-nginx-deny').value = rulesData.nginx_deny_snippet || '';
    document.getElementById('snippet-fail2ban').value = rulesData.fail2ban_filter_snippet || '';

    const tbody = document.getElementById('threats-table-body');
    tbody.innerHTML = '';
    (threatData.recent_threat_events || []).forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="white-space: nowrap;">${r.timestamp}</td>
        <td><code>${r.ip}</code></td>
        <td style="max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(r.path)}"><code>${escapeHtml(r.path)}</code></td>
        <td><span class="badge ${r.status >= 400 ? 'badge-danger' : 'badge-success'}">${r.status}</span></td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(r.user_agent)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading Security Tab', err);
  }
}

function setupGlobalDateFilter() {
  const startInput = document.getElementById('global-start-date');
  const endInput = document.getElementById('global-end-date');

  // Populate from localStorage
  if (globalStartDate) startInput.value = globalStartDate;
  if (globalEndDate) endInput.value = globalEndDate;

  // Restore checkboxes state
  document.querySelectorAll('.status-cb').forEach(cb => {
    cb.checked = globalStatuses.includes(cb.value);

    cb.addEventListener('change', () => {
      globalStatuses = getSelectedCheckboxes();
      localStorage.setItem('nginx_statuses', JSON.stringify(globalStatuses));
      currentPage = 1;
      refreshAllData();
    });
  });

  // Quick Date Presets Handler
  document.querySelectorAll('.btn-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      const preset = btn.getAttribute('data-preset');
      const now = new Date();
      let start = new Date();

      if (preset === '1h') start.setHours(now.getHours() - 1);
      else if (preset === '24h') start.setHours(now.getHours() - 24);
      else if (preset === '7d') start.setDate(now.getDate() - 7);
      else if (preset === 'all') {
        globalStartDate = '';
        globalEndDate = '';
        startInput.value = '';
        endInput.value = '';
        localStorage.removeItem('nginx_start_date');
        localStorage.removeItem('nginx_end_date');
        currentPage = 1;
        refreshAllData();
        return;
      }

      const toIsoLocal = (d) => new Date(d.getTime() - (d.getTimezoneOffset() * 60000)).toISOString().slice(0, 16);
      globalStartDate = toIsoLocal(start);
      globalEndDate = toIsoLocal(now);

      startInput.value = globalStartDate;
      endInput.value = globalEndDate;

      localStorage.setItem('nginx_start_date', globalStartDate);
      localStorage.setItem('nginx_end_date', globalEndDate);

      currentPage = 1;
      refreshAllData();
    });
  });

  // Export CSV & JSON Handlers
  document.getElementById('btn-export-csv').addEventListener('click', () => {
    const q = getGlobalDateQueryParams();
    window.location.href = `/api/export/csv?${q}`;
  });

  document.getElementById('btn-export-json').addEventListener('click', () => {
    const q = getGlobalDateQueryParams();
    window.location.href = `/api/export/json?${q}`;
  });

  // Auto-save on date change
  startInput.addEventListener('change', () => {
    globalStartDate = startInput.value;
    localStorage.setItem('nginx_start_date', globalStartDate);
    currentPage = 1;
    refreshAllData();
  });

  endInput.addEventListener('change', () => {
    globalEndDate = endInput.value;
    localStorage.setItem('nginx_end_date', globalEndDate);
    currentPage = 1;
    refreshAllData();
  });

  document.getElementById('btn-clear-global-date').addEventListener('click', () => {
    globalStartDate = '';
    globalEndDate = '';
    globalStatuses = ['2xx','3xx','403','404','5xx'];

    startInput.value = '';
    endInput.value = '';
    document.querySelectorAll('.status-cb').forEach(cb => cb.checked = true);

    localStorage.removeItem('nginx_start_date');
    localStorage.removeItem('nginx_end_date');
    localStorage.removeItem('nginx_statuses');

    currentPage = 1;
    refreshAllData();
  });



  document.getElementById('btn-copy-api-url').addEventListener('click', () => {
    const currentTab = window.location.hash.replace('#', '') || 'overview';
    let apiPath = '/api/summary';

    if (currentTab === 'googlebot') apiPath = '/api/analytics/googlebot';
    else if (currentTab === 'crawlers') apiPath = '/api/analytics/bots';
    else if (currentTab === 'ip-analytics') apiPath = '/api/analytics/ip-grouping';
    else if (currentTab === 'status-matrix') apiPath = '/api/analytics/status-matrix';
    else if (currentTab === 'access-denied') apiPath = '/api/analytics/access-denied';
    else if (currentTab === 'log-viewer') apiPath = '/api/logs';

    const query = getGlobalDateQueryParams();
    const fullUrl = `${window.location.origin}${apiPath}${query ? '?' + query : ''}`;

    navigator.clipboard.writeText(fullUrl).then(() => {
      const btn = document.getElementById('btn-copy-api-url');
      const origText = btn.innerText;
      btn.innerText = '✅ Copied!';
      setTimeout(() => { btn.innerText = origText; }, 2000);
    }).catch(err => {
      prompt('Copy API URL:', fullUrl);
    });
  });
}


function setupTabNavigation() {

  const navBtns = document.querySelectorAll('.nav-btn');
  const tabs = document.querySelectorAll('.tab-content');

  function activateTab(targetTab) {
    navBtns.forEach(b => {
      const isTarget = b.getAttribute('data-tab') === targetTab;
      b.classList.toggle('active', isTarget);
    });

    tabs.forEach(t => {
      t.classList.toggle('active', t.id === `tab-${targetTab}`);
    });
  }

  navBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      const targetTab = e.currentTarget.getAttribute('data-tab');
      if (targetTab) {
        window.location.hash = targetTab;
        activateTab(targetTab);
      }
    });
  });


  // Handle initial page load with hash or fallback to overview
  const initialHash = window.location.hash.replace('#', '');
  if (initialHash && document.getElementById(`tab-${initialHash}`)) {
    activateTab(initialHash);
  } else {
    activateTab('overview');
  }

  // Handle browser back/forward or hash change
  window.addEventListener('hashchange', () => {
    const currentHash = window.location.hash.replace('#', '') || 'overview';
    if (document.getElementById(`tab-${currentHash}`)) {
      activateTab(currentHash);
    }
  });
}


async function fetchSummary() {
  try {
    const q = getGlobalDateQueryParams();
    const res = await fetch(`/api/summary?${q}`);
    const data = await res.json();

    document.getElementById('stat-total-logs').innerText = data.totalLogs.toLocaleString();
    document.getElementById('stat-unique-ips').innerText = data.uniqueIPs.toLocaleString();
    document.getElementById('stat-googlebot').innerText = data.googlebotCount.toLocaleString();
    document.getElementById('stat-googlebot-failed').innerText = data.googlebotFailed.toLocaleString();
    document.getElementById('stat-403').innerText = data.total403.toLocaleString();
    document.getElementById('stat-bandwidth').innerText = `${data.totalBandwidthGB} GB`;
    
    document.getElementById('google-fail-badge').innerText = `${data.googlebotFailed.toLocaleString()} Failed Crawls`;
  } catch (err) {
    console.error('Failed to fetch summary metrics', err);
  }
}

async function loadOverviewCharts() {
  try {
    const q = getGlobalDateQueryParams();
    const [statusRes, botRes] = await Promise.all([
      fetch(`/api/analytics/status-matrix?${q}`),
      fetch(`/api/analytics/bots?${q}`)
    ]);

    const statusData = await statusRes.json();
    const botData = await botRes.json();

    // 1. Status Chart
    const statusCtx = document.getElementById('statusChart').getContext('2d');
    if (statusChartInstance) statusChartInstance.destroy();

    statusChartInstance = new Chart(statusCtx, {
      type: 'doughnut',
      data: {
        labels: statusData.map(d => `HTTP ${d.code}`),
        datasets: [{
          data: statusData.map(d => d.count),
          backgroundColor: ['#4ade80', '#38bdf8', '#fbbf24', '#f87171', '#a855f7', '#ec4899']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } }
      }
    });

    // 2. Bot Chart
    const botCtx = document.getElementById('botChart').getContext('2d');
    if (botChartInstance) botChartInstance.destroy();

    const topBots = botData.slice(0, 7);
    botChartInstance = new Chart(botCtx, {
      type: 'bar',
      data: {
        labels: topBots.map(b => b.category),
        datasets: [{
          label: 'Requests',
          data: topBots.map(b => b.total_requests),
          backgroundColor: '#818cf8'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#94a3b8' } },
          y: { ticks: { color: '#94a3b8' } }
        },
        plugins: { legend: { display: false } }
      }
    });

  } catch (err) {
    console.error('Error loading charts', err);
  }
}

async function loadBotsTab() {
  try {
    const q = getGlobalDateQueryParams();
    const res = await fetch(`/api/analytics/bots?${q}`);
    const bots = await res.json();

    const tbody = document.getElementById('bot-table-body');
    tbody.innerHTML = '';

    bots.forEach(b => {
      const mbUsed = (b.total_bytes / (1024 * 1024)).toFixed(2);
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${b.category}</strong></td>
        <td>${b.total_requests.toLocaleString()}</td>
        <td class="text-success">${b.success_2xx.toLocaleString()}</td>
        <td>${b.redirect_3xx.toLocaleString()}</td>
        <td class="${b.failed_4xx_5xx > 0 ? 'text-danger' : ''}">${b.failed_4xx_5xx.toLocaleString()}</td>
        <td><span class="badge ${b.forbidden_403 > 0 ? 'badge-danger' : 'badge-success'}">${b.forbidden_403}</span></td>
        <td>${mbUsed} MB</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading bots tab', err);
  }
}

async function loadGooglebotTab() {
  try {
    const q = getGlobalDateQueryParams();
    const res = await fetch(`/api/analytics/googlebot?${q}`);
    const data = await res.json();

    const tbody = document.getElementById('google-failed-table-body');
    tbody.innerHTML = '';

    data.recent_failed_crawls.forEach(l => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="white-space: nowrap;">${l.timestamp}</td>
        <td><strong>${l.ip}</strong></td>
        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(l.path)}"><code>${escapeHtml(l.path)}</code></td>
        <td><span class="badge badge-danger">${l.status}</span></td>
        <td style="max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(l.raw_message)}">${escapeHtml(l.raw_message)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading Googlebot tab', err);
  }
}

async function loadIPAnalytics() {
  try {
    const q = getGlobalDateQueryParams();
    const res = await fetch(`/api/analytics/ip-grouping?limit=100&${q}`);
    const ips = await res.json();

    const tbody = document.getElementById('ip-table-body');
    tbody.innerHTML = '';

    ips.forEach(item => {
      const errRate = item.total_requests > 0 ? ((item.error_requests / item.total_requests) * 100).toFixed(1) : '0';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="code-font"><strong>${item.ip}</strong></td>
        <td>${item.total_requests.toLocaleString()}</td>
        <td class="${item.error_requests > 0 ? 'text-danger' : ''}">${item.error_requests}</td>
        <td><span class="badge ${errRate > 50 ? 'badge-danger' : errRate > 10 ? 'badge-warning' : 'badge-success'}">${errRate}%</span></td>
        <td>${item.last_seen || 'N/A'}</td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="filterByIP('${item.ip}')">Inspect Logs</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading IP Analytics', err);
  }
}

async function loadStatusMatrixTab() {
  try {
    const q = getGlobalDateQueryParams();
    const res = await fetch(`/api/analytics/status-matrix?${q}`);
    const matrix = await res.json();

    const tbody = document.getElementById('status-matrix-table-body');
    tbody.innerHTML = '';

    matrix.forEach(m => {
      const badgeClass = m.code >= 500 ? 'badge-danger' : m.code >= 400 ? 'badge-warning' : 'badge-success';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge ${badgeClass}">HTTP ${m.code}</span></td>
        <td><strong>${m.count.toLocaleString()}</strong></td>
        <td>${m.percentage}%</td>
        <td style="max-width: 450px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${m.sample_paths.map(p => `<code>${escapeHtml(p)}</code>`).join(', ')}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading Status Matrix', err);
  }
}

async function loadAccessDeniedTab() {
  try {
    const q = getGlobalDateQueryParams();
    const res = await fetch(`/api/analytics/access-denied?${q}`);
    const data = await res.json();

    // Top offenders
    const offendersBody = document.getElementById('top-offenders-body');
    offendersBody.innerHTML = '';
    data.top_offenders.forEach(o => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong class="text-danger">${o.ip}</strong></td>
        <td><span class="badge badge-danger">${o.count}</span></td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${o.targeted_paths.map(p => `<code>${escapeHtml(p)}</code>`).join(', ')}
        </td>
      `;
      offendersBody.appendChild(tr);
    });

    // Recent denied events
    const recentBody = document.getElementById('recent-denied-body');
    recentBody.innerHTML = '';
    data.recent_events.slice(0, 20).forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${e.ip}</strong></td>
        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(e.path)}"><code>${escapeHtml(e.path)}</code></td>
        <td><span class="badge badge-danger">${e.status}</span></td>
      `;
      recentBody.appendChild(tr);
    });

  } catch (err) {
    console.error('Error loading Access Denied tab', err);
  }
}


function filterByIP(ip) {
  document.getElementById('ip-audit-input').value = ip;
  window.location.hash = 'ip-audit';
  
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  
  const targetBtn = document.querySelector('[data-tab="ip-audit"]');
  if (targetBtn) targetBtn.classList.add('active');
  document.getElementById('tab-ip-audit').classList.add('active');
  
  performIpAudit(ip);
}


async function loadLogs() {
  try {
    const query = encodeURIComponent(document.getElementById('search-query').value);
    const status = encodeURIComponent(document.getElementById('status-filter').value);
    const logType = encodeURIComponent(document.getElementById('type-filter').value);
    const dateParams = getGlobalDateQueryParams();

    const url = `/api/logs?page=${currentPage}&limit=${currentLimit}&search=${query}&status=${status}&logType=${logType}&${dateParams}`;
    const res = await fetch(url);
    const data = await res.json();


    const tbody = document.getElementById('logs-table-body');
    tbody.innerHTML = '';

    data.logs.forEach(log => {
      const tr = document.createElement('tr');
      const badgeClass = log.status >= 500 ? 'badge-danger' : log.status >= 400 ? 'badge-warning' : 'badge-success';
      
      tr.innerHTML = `
        <td><span class="badge badge-info">${log.log_type}</span></td>
        <td><strong>${log.ip}</strong></td>
        <td style="white-space: nowrap;">${log.timestamp}</td>
        <td><strong>${log.method || '-'}</strong></td>
        <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.path || log.raw_message)}">
          ${escapeHtml(log.path || log.raw_message)}
        </td>
        <td><span class="badge badge-secondary">${log.bot_category || 'Human/Other'}</span></td>
        <td><span class="badge ${badgeClass}">${log.status || '-'}</span></td>
      `;
      tbody.appendChild(tr);
    });

    document.getElementById('page-indicator').innerText = `Page ${data.pagination.page} of ${data.pagination.totalPages || 1}`;
    document.getElementById('prev-page').disabled = currentPage <= 1;
    document.getElementById('next-page').disabled = currentPage >= data.pagination.totalPages;

  } catch (err) {
    console.error('Error loading logs', err);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function setupTableSorting() {
  document.addEventListener('click', (e) => {
    const th = e.target.closest('th');
    if (!th) return;

    const table = th.closest('table');
    if (!table) return;

    const tbody = table.querySelector('tbody');
    if (!tbody) return;

    const headers = Array.from(th.parentNode.children);
    const columnIndex = headers.indexOf(th);
    const currentDirection = th.classList.contains('sort-asc') ? 'desc' : 'asc';

    headers.forEach(header => header.classList.remove('sort-asc', 'sort-desc', 'sortable'));
    headers.forEach(header => header.classList.add('sortable'));
    th.classList.add(`sort-${currentDirection}`);

    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((rowA, rowB) => {
      const cellA = rowA.children[columnIndex] ? rowA.children[columnIndex].innerText.trim() : '';
      const cellB = rowB.children[columnIndex] ? rowB.children[columnIndex].innerText.trim() : '';

      const numA = parseFloat(cellA.replace(/,/g, '').replace(/%/g, ''));
      const numB = parseFloat(cellB.replace(/,/g, '').replace(/%/g, ''));

      if (!isNaN(numA) && !isNaN(numB)) {
        return currentDirection === 'asc' ? numA - numB : numB - numA;
      }

      return currentDirection === 'asc' 
        ? cellA.localeCompare(cellB, undefined, { numeric: true, sensitivity: 'base' })
        : cellB.localeCompare(cellA, undefined, { numeric: true, sensitivity: 'base' });
    });

    rows.forEach(row => tbody.appendChild(row));
  });
}

