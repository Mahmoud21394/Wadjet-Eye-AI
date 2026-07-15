/** Jest configuration for Wadjet-Eye AI backend tests */
'use strict';

module.exports = {
  testEnvironment:   'node',
  testMatch:         ['**/tests/**/*.test.js'],
  collectCoverage:   true,
  coverageDirectory: 'coverage',
  coverageThreshold: {
    global: {
      branches:   70,
      functions:  80,
      lines:      80,
      statements: 80,
    },
  },
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/tests/',
    'server.js',       // integration - tested separately
    'workers/',        // background workers
    'routes/nexus.js', // route integration - 2062-line XORCISM integration, covered by nexus.test.js HTTP suite
    'services/nexus-scheduler.js', // background scheduler - runs in live env
  ],
  testTimeout: 30000,
  verbose:     true,
};
