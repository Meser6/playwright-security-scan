const base = require('@playwright/test');

exports.test = base.test.extend({
  user: async ({}, use) => {
    await use('alice');
  },
});
exports.expect = base.expect;
