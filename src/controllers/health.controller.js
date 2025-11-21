const healthService = require('../services/health.service');

const getStatus = (req, res, next) => {
  try {
    const payload = healthService.getStatus();
    res.status(200).json(payload);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getStatus,
};

