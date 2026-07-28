const express = require('express');
const router = express.Router();
const { logsDB, applyDateFilter } = require('../models/logStore');

// CSV Exporter Endpoint
router.get('/csv', (req, res) => {
  const { startDate, endDate, statuses, search } = req.query;
  let filtered = applyDateFilter(logsDB, startDate, endDate, statuses);

  if (search) {
    const s = search.toLowerCase();
    filtered = filtered.filter(l => 
      l.ip.toLowerCase().includes(s) || 
      l.path.toLowerCase().includes(s) || 
      l.user_agent.toLowerCase().includes(s)
    );
  }

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=nginx_logs_export.csv');

  let csvContent = 'ID,Timestamp,IP,Method,Path,Status,Size,UserAgent,BotCategory,SourceFile\n';
  
  filtered.slice(0, 10000).forEach(l => {
    const cleanPath = `"${(l.path || '').replace(/"/g, '""')}"`;
    const cleanUa = `"${(l.user_agent || '').replace(/"/g, '""')}"`;
    csvContent += `${l.id},${l.timestamp},${l.ip},${l.method},${cleanPath},${l.status},${l.size},${cleanUa},"${l.bot_category}",${l.source_file}\n`;
  });

  res.send(csvContent);
});

// JSON Exporter Endpoint
router.get('/json', (req, res) => {
  const { startDate, endDate, statuses, search, limit } = req.query;
  let filtered = applyDateFilter(logsDB, startDate, endDate, statuses);

  if (search) {
    const s = search.toLowerCase();
    filtered = filtered.filter(l => 
      l.ip.toLowerCase().includes(s) || 
      l.path.toLowerCase().includes(s) || 
      l.user_agent.toLowerCase().includes(s)
    );
  }

  const maxLimit = parseInt(limit, 10) || 5000;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename=nginx_logs_export.json');
  res.json(filtered.slice(0, maxLimit));
});

module.exports = router;
