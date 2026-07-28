const express = require('express');
const router = express.Router();
const { logsDB, applyDateFilter } = require('../models/logStore');

// 1. Crawler & Bot Traffic Breakdown
router.get('/bots', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  const botStats = {};

  filtered.forEach(log => {
    const cat = log.bot_category;
    if (!botStats[cat]) {
      botStats[cat] = {
        category: cat,
        total_requests: 0,
        success_2xx: 0,
        redirect_3xx: 0,
        failed_4xx_5xx: 0,
        forbidden_403: 0,
        not_found_404: 0,
        total_bytes: 0
      };
    }

    botStats[cat].total_requests++;
    botStats[cat].total_bytes += (log.size || 0);

    if (log.status >= 200 && log.status < 300) botStats[cat].success_2xx++;
    else if (log.status >= 300 && log.status < 400) botStats[cat].redirect_3xx++;
    else if (log.status >= 400) botStats[cat].failed_4xx_5xx++;

    if (log.status === 403) botStats[cat].forbidden_403++;
    if (log.status === 404) botStats[cat].not_found_404++;
  });

  const sorted = Object.values(botStats).sort((a, b) => b.total_requests - a.total_requests);
  res.json(sorted);
});

// 2. Googlebot Detailed Analysis
router.get('/googlebot', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  const googleLogs = filtered.filter(l => l.bot_category.includes('Google'));
  
  const failedCrawls = googleLogs.filter(l => l.status >= 400);

  const pathMap = {};
  googleLogs.forEach(l => {
    if (!pathMap[l.path]) {
      pathMap[l.path] = { path: l.path, count: 0, status_codes: {} };
    }
    pathMap[l.path].count++;
    pathMap[l.path].status_codes[l.status] = (pathMap[l.path].status_codes[l.status] || 0) + 1;
  });

  const topPaths = Object.values(pathMap)
    .sort((a, b) => b.count - a.count)
    .slice(0, 30);

  res.json({
    total_google_crawls: googleLogs.length,
    failed_google_crawls_count: failedCrawls.length,
    top_crawled_paths: topPaths,
    recent_failed_crawls: failedCrawls.slice(-50).reverse()
  });
});

// 3. Status Code Matrix
router.get('/status-matrix', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  const matrix = {};

  filtered.forEach(l => {
    const code = l.status || 'Unknown';
    if (!matrix[code]) {
      matrix[code] = {
        code,
        count: 0,
        percentage: 0,
        sample_paths: new Set()
      };
    }
    matrix[code].count++;
    if (matrix[code].sample_paths.size < 5 && l.path) {
      matrix[code].sample_paths.add(l.path);
    }
  });

  const total = filtered.length;
  const result = Object.values(matrix).map(item => ({
    code: item.code,
    count: item.count,
    percentage: total > 0 ? ((item.count / total) * 100).toFixed(2) : '0',
    sample_paths: Array.from(item.sample_paths)
  })).sort((a, b) => b.count - a.count);

  res.json(result);
});

// 4. IP Grouping
router.get('/ip-grouping', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  const ipMap = {};

  filtered.forEach(log => {
    if (log.ip === 'unknown') return;
    if (!ipMap[log.ip]) {
      ipMap[log.ip] = {
        ip: log.ip,
        total_requests: 0,
        error_requests: 0,
        last_seen: log.iso_time,
        user_agent: log.user_agent
      };
    }
    ipMap[log.ip].total_requests++;
    if (log.status >= 400) ipMap[log.ip].error_requests++;
    if (log.iso_time > ipMap[log.ip].last_seen) ipMap[log.ip].last_seen = log.iso_time;
  });

  const sortedIPs = Object.values(ipMap)
    .sort((a, b) => b.total_requests - a.total_requests)
    .slice(0, limit);

  res.json(sortedIPs);
});

// 5. Access Denied & Threat Probes
router.get('/access-denied', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  const deniedLogs = filtered.filter(l => 
    l.status === 403 || 
    l.path.includes('.php') || 
    l.path.includes('wp-admin') || 
    l.path.includes('phpinfo') || 
    l.path.includes('.env') ||
    l.path.includes('.git')
  );

  const offendersMap = {};
  deniedLogs.forEach(l => {
    if (l.ip === 'unknown') return;
    if (!offendersMap[l.ip]) {
      offendersMap[l.ip] = { ip: l.ip, count: 0, paths: new Set() };
    }
    offendersMap[l.ip].count++;
    if (offendersMap[l.ip].paths.size < 5) offendersMap[l.ip].paths.add(l.path);
  });

  const topOffenders = Object.values(offendersMap)
    .map(o => ({ ip: o.ip, count: o.count, targeted_paths: Array.from(o.paths) }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  res.json({
    total_denied_events: deniedLogs.length,
    top_offenders: topOffenders,
    recent_events: deniedLogs.slice(-100).reverse()
  });
});

module.exports = router;
