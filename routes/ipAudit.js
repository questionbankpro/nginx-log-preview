const express = require('express');
const router = express.Router();
const { logsDB, applyDateFilter } = require('../models/logStore');

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

  // Filter logs for this specific IP & active global date/status filters
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

  // Apply internal path search filter
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
