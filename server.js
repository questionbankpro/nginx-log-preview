const path = require('path');
const express = require('express');
const { loadLogs } = require('./models/logStore');

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, 'logs');

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Feature Modular Routes
app.use('/api', require('./routes/summary'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/ip-audit', require('./routes/ipAudit'));

// Start Server
loadLogs(LOG_DIR).then(() => {
  app.listen(PORT, () => {
    console.log(`Nginx Advanced Log Analyzer running at http://localhost:${PORT}`);
  });
});
