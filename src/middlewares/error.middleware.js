const createError = require('http-errors');
const httpStatus = require('http-status');
const logger = require('../utils/logger');

const notFoundHandler = (req, res, next) => {
  next(createError(httpStatus.NOT_FOUND, `Route ${req.originalUrl} not found`));
};

// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  const statusCode = err.status || httpStatus.INTERNAL_SERVER_ERROR;
  const response = {
    status: 'error',
    message: err.message || 'Unexpected server error',
  };

  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  if (statusCode >= 500) {
    logger.error({ err }, 'Unhandled application error');
  }

  res.status(statusCode).json(response);
};

module.exports = {
  notFoundHandler,
  errorHandler,
};

