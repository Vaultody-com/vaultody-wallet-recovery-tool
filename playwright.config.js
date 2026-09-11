'use strict';

const {defineConfig} = require('@playwright/test');

module.exports = defineConfig({
    testDir: './tests',
    // One Electron app instance at a time — the app is a single-window desktop tool.
    workers: 1,
    fullyParallel: false,
    timeout: 60_000,
    expect: {timeout: 10_000},
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    reporter: process.env.CI ? [['list'], ['github']] : [['list']],
});
