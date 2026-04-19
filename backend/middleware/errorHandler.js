/**
 * Global Error Handler Middleware
 */
'use strict';

function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;
  const isDev  = process.env.NODE_ENV === 'development';

  console.error(`[Error] ${req.method} ${req.path} → ${status}: ${err.message}`);

  res.status(status).json({
    error:   err.message || 'Internal Server Error',
    code:    err.code    || 'INTERNAL_ERROR',
    path:    req.path,
    ...(isDev ? { stack: err.stack } : {})
  });
}

/* Wrap async route handlers to catch rejections */
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

/* Create typed HTTP errors */
function createError(status, message, code) {
  const err = new Error(message);
  err.status = status;
  err.code   = code;
  return err;
}

module.exports = { errorHandler, asyncHandler, createError };
