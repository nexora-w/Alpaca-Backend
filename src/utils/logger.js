const pino = require('pino');
const config = require('../config/env');

const logger = pino({
  level: config.logging.level,
  redact: ['req.headers.authorization'],
  base: {
    env: config.env,
    app: config.app.name,
  },
});

logger.stream = {
  write: (message) => logger.info(message.trim()),
};

module.exports = logger;

