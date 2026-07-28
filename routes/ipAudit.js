const express = require('express');
const router = express.Router();
const { logsDB, applyDateFilter } = require('../models/logStore');

// CIDR Subnet Range Audit (/24 & /16)
router.get('/subnet', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  
  const subnets24 = {};
  filtered.forEach(log => {
    if (!log.ip || log.ip === 'unknown') return;
    const parts = log.ip.split('.');
    if (parts.length === 4) {
      const s24 = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
      if (!subnets24[s24]) {
        subnets24[s24] = { subnet: s24, total_requests: 0, unique_ips: new Set(), errors: 0 };
      }
      subnets24[s24].total_requests++;
      subnets24[s24].unique_ips.add(log.ip);
      if (log.status >= 400) subnets24[s24].errors++;
    }
  });

  const sortedSubnets = Object.values(subnets24)
    .map(s => ({
      subnet: s.subnet,
      total_requests: s.total_requests,
      unique_ips_count: s.unique_ips.size,
      error_requests: s.errors
    }))
    .sort((a, b) => b.total_requests - a.total_requests)
    .slice(0, 30);

  res.json(sortedSubnets);
});

// Single IP Deep-Dive Audit Endpoint with Paginated Log Exploration
router.get('/', (req, res) => {
  const targetIp = (req.query.ip || '').trim();
  if (!targetIp) {
    return res.status(400).json({ error: 'IP parameter is required' });
  }

  const { startDate, endDate, statuses } = req.query;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 100;
  const search = (req.query.search || '').toLowerCase();

  let ipLogs = applyDateFilter(logsDB, startDate, endDate, statuses).filter(l => l.ip === targetIp);
  
  const totalRequests = ipLogs.length;
  const userAgents = Array.from(new Set(ipLogs.map(l => l.user_agent)));
  const botCategories = Array.from(new Set(ipLogs.map(l => l.bot_category)));
  
  const statusCounts = {};
  ipLogs.forEach(l => {
    statusCounts[l.status] = (statusCounts[l.status] || 0) + 1;
  });

  const pathMap = {};
  ipLogs.forEach(l => {
    if (!pathMap[l.path]) {
      pathMap[l.path] = { path: l.path, count: 0, status: l.status };
    }
    pathMap[l.path].count++;
  });

  const topPaths = Object.values(pathMap).sort((a, b) => b.count - a.count).slice(0, 50);

  let paginatedLogs = ipLogs;
  if (search) {
    paginatedLogs = paginatedLogs.filter(l => l.path.toLowerCase().includes(search) || l.raw_message.toLowerCase().includes(search));
  }

  const subTotal = paginatedLogs.length;
  const totalPages = Math.ceil(subTotal / limit);
  const offset = (page - 1) * limit;
  const logs = paginatedLogs.slice().reverse().slice(offset, offset + limit);

  res.json({
    searched_ip: targetIp,
    matched_logs_count: totalRequests,
    status_summary: statusCounts,
    user_agents: userAgents,
    bot_categories: botCategories,
    top_paths: topPaths,
    logs,
    pagination: {
      total: subTotal,
      page,
      limit,
      totalPages: totalPages || 1
    }
  });
});

module.exports = router;
