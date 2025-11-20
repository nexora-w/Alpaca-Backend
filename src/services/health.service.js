const os = require('os');

const getStatus = () => ({
  status: 'ok',
  uptime: process.uptime(),
  timestamp: new Date().toISOString(),
  version: process.env.npm_package_version,
  host: os.hostname(),
});

module.exports = {
  getStatus,
};

