const express = require('express');
const router = express.Router();
const { logsDB, applyDateFilter } = require('../models/logStore');

// Summary Endpoint
router.get('/summary', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);

  const totalLogs = filtered.length;
  const uniqueIPs = new Set(filtered.filter(l => l.ip !== 'unknown').map(l => l.ip)).size;
  const total2xx = filtered.filter(l => l.status >= 200 && l.status < 300).length;
  const total3xx = filtered.filter(l => l.status >= 300 && l.status < 400).length;
  const total4xx = filtered.filter(l => l.status >= 400 && l.status < 500).length;
  const total5xx = filtered.filter(l => l.status >= 500).length;
  const total403 = filtered.filter(l => l.status === 403).length;
  const total404 = filtered.filter(l => l.status === 404).length;
  
  const googlebotCount = filtered.filter(l => l.bot_category.includes('Google')).length;
  const googlebotFailed = filtered.filter(l => l.bot_category.includes('Google') && l.status >= 400).length;
  
  const totalBots = filtered.filter(l => l.bot_category !== 'Regular Human Browser / Other').length;
  const totalBandwidthBytes = filtered.reduce((acc, curr) => acc + (curr.size || 0), 0);

  res.json({
    totalLogs,
    uniqueIPs,
    total2xx,
    total3xx,
    total4xx,
    total5xx,
    total403,
    total404,
    googlebotCount,
    googlebotFailed,
    totalBots,
    totalBandwidthGB: (totalBandwidthBytes / (1024 * 1024 * 1024)).toFixed(2)
  });
});

// Paginated Raw Logs Endpoint
router.get('/logs', (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 50;
  const search = (req.query.search || '').toLowerCase();
  const status = req.query.status ? parseInt(req.query.status, 10) : null;
  const logType = req.query.logType || '';
  const botCategory = req.query.botCategory || '';
  const { startDate, endDate, statuses } = req.query;

  let filtered = applyDateFilter(logsDB, startDate, endDate, statuses);

  if (search) {
    filtered = filtered.filter(l => 
      l.ip.toLowerCase().includes(search) || 
      l.path.toLowerCase().includes(search) || 
      l.user_agent.toLowerCase().includes(search) || 
      l.raw_message.toLowerCase().includes(search)
    );
  }

  if (status) filtered = filtered.filter(l => l.status === status);
  if (logType) filtered = filtered.filter(l => l.log_type === logType);
  if (botCategory) filtered = filtered.filter(l => l.bot_category === botCategory);

  const total = filtered.length;
  const totalPages = Math.ceil(total / limit);
  const offset = (page - 1) * limit;
  const logs = filtered.slice(offset, offset + limit);

  res.json({ logs, pagination: { total, page, limit, totalPages } });
});

module.exports = router;
