const createError = require('http-errors');
const logger = require('../utils/logger');

const notFoundHandler = (req, res, next) => {
  next(createError(404, `Route ${req.originalUrl} not found`));
};

// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  // Ensure statusCode is a valid number
  let statusCode = err.status || err.statusCode;
  
  // Validate statusCode is a number between 100-599
  if (typeof statusCode !== 'number' || statusCode < 100 || statusCode >= 600) {
    statusCode = 500; // Default to 500 Internal Server Error
  }

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

