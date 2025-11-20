const httpStatus = require('http-status');
const healthService = require('../services/health.service');

const getStatus = (req, res, next) => {
  try {
    const payload = healthService.getStatus();
    res.status(httpStatus.OK).json(payload);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getStatus,
};

