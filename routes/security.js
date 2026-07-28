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

// 3. Automated Fail2ban & Nginx Security Rule Generator API
router.get('/rules-generator', (req, res) => {
  const { startDate, endDate } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate);
  
  const badIPs = new Set();
  filtered.forEach(log => {
    if (log.status === 403 || log.path.includes('.env') || log.path.includes('wp-admin') || log.path.includes('phpinfo')) {
      if (log.ip !== 'unknown') badIPs.add(log.ip);
    }
  });

  const ipList = Array.from(badIPs);
  const nginxDenyRules = ipList.length > 0 ? ipList.map(ip => `deny ${ip};`).join('\n') : '# No threat IPs currently flagged';
  
  const fail2banFilter = `# /etc/fail2ban/filter.d/nginx-scanners.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(\\..env|wp-admin|wp-config|phpinfo|\\.\\./|\\.git|credentials\\.json).*"\n
ignoreregex =
`;

  const fail2banJail = `# /etc/fail2ban/jail.d/nginx-scanners.local
[nginx-scanners]
enabled  = true
port     = http,https
filter   = nginx-scanners
logpath  = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime  = 86400
action   = iptables-multiport[name=nginx-scanners, port="http,https", protocol=tcp]
`;

  res.json({
    offending_ips_count: ipList.length,
    offending_ips: ipList.slice(0, 50),
    nginx_deny_snippet: nginxDenyRules,
    fail2ban_filter_snippet: fail2banFilter,
    fail2ban_jail_snippet: fail2banJail
  });
});

// Downloadable File 1: nginx_block_scanners.conf
router.get('/download/nginx-block', (req, res) => {
  const { startDate, endDate } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate);
  
  const badIPs = new Set();
  filtered.forEach(log => {
    if (log.status === 403 || log.path.includes('.env') || log.path.includes('wp-admin') || log.path.includes('phpinfo')) {
      if (log.ip !== 'unknown') badIPs.add(log.ip);
    }
  });

  const ipList = Array.from(badIPs);
  let content = `# Nginx Blocked Malicious Scanner IPs\n# Generated automatically at: ${new Date().toISOString()}\n\n`;
  content += ipList.length > 0 ? ipList.map(ip => `deny ${ip};`).join('\n') : '# No bad IPs detected\n';

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename=nginx_block_scanners.conf');
  res.send(content);
});

// Downloadable File 2: nginx-scanners.conf (Fail2ban Filter)
router.get('/download/fail2ban-filter', (req, res) => {
  const content = `# /etc/fail2ban/filter.d/nginx-scanners.conf
# Generated automatically by Nginx Insights Suite

[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(\\..env|wp-admin|wp-config|phpinfo|\\.\\./|\\.git|credentials\\.json).*"\n
ignoreregex =
`;
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename=nginx-scanners.conf');
  res.send(content);
});

// Downloadable File 3: nginx-scanners.local (Fail2ban Jail)
router.get('/download/fail2ban-jail', (req, res) => {
  const content = `# /etc/fail2ban/jail.d/nginx-scanners.local
# Generated automatically by Nginx Insights Suite

[nginx-scanners]
enabled  = true
port     = http,https
filter   = nginx-scanners
logpath  = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime  = 86400
action   = iptables-multiport[name=nginx-scanners, port="http,https", protocol=tcp]
`;
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename=nginx-scanners.local');
  res.send(content);
});

// Downloadable File 4: SECURITY_SETUP_GUIDE.md
router.get('/download/setup-guide', (req, res) => {
  const { startDate, endDate } = req.query;
  const filtered = applyDateFilter(logsDB, startDate, endDate);
  
  const badIPs = new Set();
  filtered.forEach(log => {
    if (log.status === 403 || log.path.includes('.env') || log.path.includes('wp-admin')) {
      if (log.ip !== 'unknown') badIPs.add(log.ip);
    }
  });

  const ipList = Array.from(badIPs);

  let doc = `# 🛡️ Complete Nginx & Fail2ban Security Hardening Guide

Generated automatically based on active log analysis (${ipList.length} threat IPs identified).

---

## 📋 Table of Contents
1. [Overview](#1-overview)
2. [Step 1: Apply Instant Nginx IP Blocks](#step-1-apply-instant-nginx-ip-blocks)
3. [Step 2: Install & Enable Fail2ban](#step-2-install--enable-fail2ban)
4. [Step 3: Configure Fail2ban Custom Scanner Filter](#step-3-configure-fail2ban-custom-scanner-filter)
5. [Step 4: Configure Fail2ban Custom Jail](#step-4-configure-fail2ban-custom-jail)
6. [Step 5: Verify & Test Banned IPs](#step-5-verify--test-banned-ips)

---

## 1. Overview
Your server logs revealed **${ipList.length} offending IPs** attempting unauthorized access to sensitive files (\`.env\`, \`wp-admin\`, \`phpinfo\`, etc.).

This guide provides exact terminal commands to block these IPs instantly via Nginx and automate future IP bans using Fail2ban.

---

## Step 1: Apply Instant Nginx IP Blocks

1. Download \`nginx_block_scanners.conf\` or create the file on your server:
   \`\`\`bash
   sudo nano /etc/nginx/conf.d/nginx_block_scanners.conf
   \`\`\`

2. Paste your generated IP block directives:
   \`\`\`nginx
${ipList.slice(0, 30).map(ip => `deny ${ip};`).join('\n')}
   \`\`\`

3. Include the block file inside your main \`/etc/nginx/nginx.conf\` (inside the \`http {}\` block if not using \`conf.d\`):
   \`\`\`nginx
   include /etc/nginx/conf.d/nginx_block_scanners.conf;
   \`\`\`

4. Test Nginx syntax and reload:
   \`\`\`bash
   sudo nginx -t
   sudo systemctl reload nginx
   \`\`\`

---

## Step 2: Install & Enable Fail2ban

If Fail2ban is not yet installed on your Linux server, run the command for your OS:

### Ubuntu / Debian:
\`\`\`bash
sudo apt update
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
\`\`\`

### RHEL / CentOS / AlmaLinux:
\`\`\`bash
sudo dnf install epel-release -y
sudo dnf install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
\`\`\`

---

## Step 3: Configure Fail2ban Custom Scanner Filter

1. Create the custom scanner filter definition file:
   \`\`\`bash
   sudo nano /etc/fail2ban/filter.d/nginx-scanners.conf
   \`\`\`

2. Paste the following regex definition:
   \`\`\`ini
   [Definition]
   failregex = ^<HOST> -.*"(GET|POST|HEAD).*(\\..env|wp-admin|wp-config|phpinfo|\\.\\./|\\.git|credentials\\.json).*"\n
   ignoreregex =
   \`\`\`

---

## Step 4: Configure Fail2ban Custom Jail

1. Create the jail configuration file:
   \`\`\`bash
   sudo nano /etc/fail2ban/jail.d/nginx-scanners.local
   \`\`\`

2. Paste the jail rules:
   \`\`\`ini
   [nginx-scanners]
   enabled  = true
   port     = http,https
   filter   = nginx-scanners
   logpath  = /var/log/nginx/access.log
   maxretry = 2
   findtime = 600
   bantime  = 86400
   action   = iptables-multiport[name=nginx-scanners, port="http,https", protocol=tcp]
   \`\`\`

3. Restart Fail2ban to activate the new jail:
   \`\`\`bash
   sudo systemctl restart fail2ban
   \`\`\`

---

## Step 5: Verify & Test Banned IPs

1. Check active Fail2ban jail status:
   \`\`\`bash
   sudo fail2ban-client status nginx-scanners
   \`\`\`

2. View list of currently banned IP addresses:
   \`\`\`bash
   sudo iptables -L -n -v | grep DROP
   \`\`\`

3. Manually unban an IP if needed:
   \`\`\`bash
   sudo fail2ban-client set nginx-scanners unbanip <IP_ADDRESS>
   \`\`\`
`;

  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', 'attachment; filename=SECURITY_SETUP_GUIDE.md');
  res.send(doc);
});

module.exports = router;

