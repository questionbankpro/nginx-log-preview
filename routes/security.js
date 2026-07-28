const express = require('express');
const router = express.Router();
const { logsDB, applyDateFilter } = require('../models/logStore');

// 1. Threat Probes (LFI/RFI, SQLi, Sensitive Files)
router.get('/threats', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);

  const threatPatterns = [
    { name: 'Environment File Probe', pattern: /\.env/i },
    { name: 'Directory Traversal (LFI)', pattern: /\.\.[\/\\]/i },
    { name: 'WordPress Admin Probe', pattern: /wp-admin|wp-config|xmlrpc/i },
    { name: 'PHP File Inspection', pattern: /phpinfo|eval\(|base64_/i },
    { name: 'SQL Injection Attack', pattern: /select\s+.*from|union\s+select|information_schema/i },
    { name: 'Git Repository Leak Scan', pattern: /\.git\//i },
    { name: 'AWS Credentials Scan', pattern: /aws|\.aws\/credentials|credentials\.json/i }
  ];

  const threatsMap = {};
  threatPatterns.forEach(tp => {
    threatsMap[tp.name] = { name: tp.name, count: 0, sample_ips: new Set(), sample_paths: new Set() };
  });

  const suspiciousLogs = [];

  filtered.forEach(log => {
    let matched = false;
    threatPatterns.forEach(tp => {
      if (tp.pattern.test(log.path) || tp.pattern.test(log.raw_message)) {
        threatsMap[tp.name].count++;
        if (log.ip !== 'unknown') threatsMap[tp.name].sample_ips.add(log.ip);
        if (threatsMap[tp.name].sample_paths.size < 5) threatsMap[tp.name].sample_paths.add(log.path);
        matched = true;
      }
    });

    if (matched || log.status === 403) {
      suspiciousLogs.push(log);
    }
  });

  const threatSummary = Object.values(threatsMap).map(t => ({
    name: t.name,
    count: t.count,
    unique_ips_count: t.sample_ips.size,
    sample_paths: Array.from(t.sample_paths)
  })).filter(t => t.count > 0);

  res.json({
    total_threat_events: suspiciousLogs.length,
    threat_categories: threatSummary,
    recent_threat_events: suspiciousLogs.slice(-100).reverse()
  });
});

// 2. High Frequency IP Spike Detector (Brute-Force / Rate Limit)
router.get('/spikes', (req, res) => {
  const { startDate, endDate, statuses } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate, statuses);
  const ipCounts = {};

  filtered.forEach(log => {
    if (log.ip === 'unknown') return;
    if (!ipCounts[log.ip]) {
      ipCounts[log.ip] = { ip: log.ip, count: 0, error_count: 0, bot_category: log.bot_category };
    }
    ipCounts[log.ip].count++;
    if (log.status >= 400) ipCounts[log.ip].error_count++;
  });

  const spikes = Object.values(ipCounts)
    .filter(item => item.count >= 20)
    .sort((a, b) => b.count - a.count);

  res.json(spikes.slice(0, 50));
});

// 3. Automated Fail2ban & Nginx Rate-Limit Rule Generator
router.get('/rules-generator', (req, res) => {
  const { startDate, endDate } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate);
  
  const badIPs = new Set();
  filtered.forEach(log => {
    if (log.status === 403 || log.path.includes('.env') || log.path.includes('wp-login')) {
      if (log.ip !== 'unknown') badIPs.add(log.ip);
    }
  });

  const ipList = Array.from(badIPs);

  const nginxDenyRules = ipList.map(ip => `deny ${ip};`).join('\n');
  const fail2banFilter = `[Definition]\nfailregex = ^<HOST> -.*"(GET|POST).*(\\..env|wp-admin|phpinfo|\\.\\./).*"\n`;

  res.json({
    offending_ips_count: ipList.length,
    offending_ips: ipList.slice(0, 50),
    nginx_deny_snippet: nginxDenyRules || '# No bad IPs detected',
    fail2ban_filter_snippet: fail2banFilter
  });
});

module.exports = router;
