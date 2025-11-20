const http = require('http');
const app = require('./app');
const config = require('./config/env');
const logger = require('./utils/logger');

const server = http.createServer(app);

const startServer = () => {
  server.listen(config.port, () => {
    logger.info(`🚀 ${config.app.name} listening on port ${config.port} (${config.env})`);
  });
};

const gracefulShutdown = (signal) => {
  logger.info(`${signal} received. Closing server...`);
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
};

['SIGINT', 'SIGTERM'].forEach((signal) => {
  process.on(signal, () => gracefulShutdown(signal));
});

process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception, exiting');
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error({ reason }, 'Unhandled promise rejection');
});

startServer();

