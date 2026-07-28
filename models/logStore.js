const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const readline = require('readline');

// In-Memory Global Log Storage
const logsDB = [];

const ACCESS_REGEX = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.*?) \S+" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;

function parseAccessLogLine(line, file) {
  const match = line.match(ACCESS_REGEX);
  if (match) {
    const ip = match[1];
    const timestamp = match[2];
    const method = match[3];
    const rawPath = match[4];
    const status = parseInt(match[5], 10);
    const size = match[6] === '-' ? 0 : parseInt(match[6], 10);
    const referrer = match[7] || '';
    const userAgent = match[8] || '';

    const botCategory = classifyBot(userAgent);

    return {
      id: logsDB.length + 1,
      log_type: 'access',
      ip,
      timestamp,
      iso_time: parseLogDate(timestamp),
      method,
      path: rawPath,
      status,
      size,
      referrer,
      user_agent: userAgent,
      bot_category: botCategory,
      raw_message: line,
      source_file: file
    };
  }
  return null;
}

function parseErrorLogLine(line, file) {
  const ipMatch = line.match(/client:\s*([^\s,]+)/);
  const reqMatch = line.match(/request:\s*"(\S+)\s+(.*?)\s+HTTP\/[^"]*"/);
  const status = line.includes('access forbidden') ? 403 : 500;
  const timeMatch = line.match(/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})/);

  return {
    id: logsDB.length + 1,
    log_type: 'error',
    ip: ipMatch ? ipMatch[1] : 'unknown',
    timestamp: timeMatch ? timeMatch[1] : '',
    iso_time: timeMatch ? timeMatch[1].replace(/\//g, '-') : '',
    method: reqMatch ? reqMatch[1] : '',
    path: reqMatch ? reqMatch[2] : '',
    status: status,
    size: 0,
    referrer: '',
    user_agent: '',
    bot_category: 'Unknown/Error Log',
    raw_message: line,
    source_file: file
  };
}

function classifyBot(ua) {
  if (!ua || ua === '-') return 'Empty User-Agent';
  const u = ua.toLowerCase();

  if (u.includes('googlebot')) return 'Googlebot (Search)';
  if (u.includes('google-inspectiontool')) return 'Google Inspection Tool';
  if (u.includes('mediapartners-google')) return 'Google AdSense';
  if (u.includes('bingbot') || u.includes('bingpreview')) return 'Bingbot (Microsoft)';
  if (u.includes('yandexbot')) return 'Yandex Bot';
  if (u.includes('duckduckbot')) return 'DuckDuckGo Bot';
  if (u.includes('baiduspider')) return 'Baidu Spider';
  if (u.includes('ahrefsbot')) return 'Ahrefs SEO Crawler';
  if (u.includes('semrushbot')) return 'Semrush SEO Crawler';
  if (u.includes('mj12bot')) return 'Majestic SEO Bot';
  if (u.includes('bytespider')) return 'ByteDance/TikTok Spider';
  if (u.includes('gptbot')) return 'OpenAI GPTBot';
  if (u.includes('claudebot') || u.includes('anthropic')) return 'Anthropic ClaudeBot';
  if (u.includes('perplexitybot')) return 'Perplexity AI Bot';
  if (u.includes('meta-externalagent') || u.includes('facebookexternalhit')) return 'Meta/Facebook Crawler';
  if (u.includes('applebot')) return 'Applebot';
  if (u.includes('amazonbot')) return 'Amazonbot';
  if (u.includes('python') || u.includes('curl') || u.includes('wget') || u.includes('go-http-client') || u.includes('axios')) return 'Scripting Tool (Python/cURL/Go)';
  if (u.includes('micromessenger')) return 'WeChat MicroMessenger';
  
  return 'Regular Human Browser / Other';
}

function parseLogDate(dateStr) {
  try {
    const months = { Jan:'01', Feb:'02', Mar:'03', Apr:'04', May:'05', Jun:'06', Jul:'07', Aug:'08', Sep:'09', Oct:'10', Nov:'11', Dec:'12' };
    const m = dateStr.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
    if (m) {
      return `${m[3]}-${months[m[2]] || '01'}-${m[1]} ${m[4]}`;
    }
  } catch (e) {}
  return dateStr;
}

async function loadLogs(logDir) {
  const targetDir = fs.existsSync(logDir) ? logDir : path.join(__dirname, '..');
  
  if (!fs.existsSync(targetDir)) {
    console.log(`Directory ${targetDir} does not exist. Creating it...`);
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const files = fs.readdirSync(targetDir);
  const logFiles = files.filter(f => f.startsWith('access.log') || f.startsWith('error.log'));

  if (logFiles.length === 0) {
    console.log(`⚠️ No access.log or error.log files found in ${targetDir}. Please add your Nginx log files to this folder.`);
    logsDB.length = 0;
    return;
  }

  console.log(`Loading ${logFiles.length} log files from ${targetDir}...`);
  logsDB.length = 0; // reset


  for (const file of logFiles) {
    const filePath = path.join(targetDir, file);
    const isGz = file.endsWith('.gz');
    const isErrorLog = file.startsWith('error.log');

    let stream = fs.createReadStream(filePath);
    if (isGz) stream = stream.pipe(zlib.createGunzip());

    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    for await (const line of rl) {
      if (!line.trim()) continue;
      let parsed = isErrorLog ? parseErrorLogLine(line, file) : parseAccessLogLine(line, file);
      if (!parsed && !isErrorLog) {
        parsed = {
          id: logsDB.length + 1, log_type: 'access', ip: 'unknown', timestamp: '', iso_time: '',
          method: 'GET', path: line, status: 200, size: 0, referrer: '', user_agent: '',
          bot_category: 'Unknown', raw_message: line, source_file: file
        };
      }
      if (parsed) logsDB.push(parsed);
    }
  }
  console.log(`Loaded ${logsDB.length} records into memory.`);
}

function applyDateFilter(logs, startDate, endDate, statuses) {
  let result = logs;
  if (startDate) {
    const normStart = startDate.replace('T', ' ');
    result = result.filter(l => l.iso_time && l.iso_time >= normStart);
  }
  if (endDate) {
    const normEnd = endDate.replace('T', ' ');
    result = result.filter(l => l.iso_time && l.iso_time <= normEnd);
  }
  if (statuses && statuses.length > 0) {
    const list = Array.isArray(statuses) ? statuses : statuses.split(',');
    result = result.filter(l => {
      const st = l.status;
      if (list.includes('2xx') && st >= 200 && st < 300) return true;
      if (list.includes('3xx') && st >= 300 && st < 400) return true;
      if (list.includes('403') && st === 403) return true;
      if (list.includes('404') && st === 404) return true;
      if (list.includes('5xx') && st >= 500) return true;
      return false;
    });
  }
  return result;
}

module.exports = {
  logsDB,
  loadLogs,
  applyDateFilter
};
