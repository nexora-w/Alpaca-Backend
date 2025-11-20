const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const compression = require('compression');
const routes = require('./routes');
const config = require('./config/env');
const logger = require('./utils/logger');
const { notFoundHandler, errorHandler } = require('./middlewares/error.middleware');

const app = express();

app.disable('x-powered-by');

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(compression());

if (config.env !== 'test') {
  app.use(
    morgan('combined', {
      stream: logger.stream,
    })
  );
}

app.get('/status', (req, res) => {
  res.json({
    status: 'ok',
    service: config.app.name,
    env: config.env,
  });
});

app.use('/api', routes);

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;

