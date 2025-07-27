// @ts-check
// Requires globally installed Playwright: npm install -g @playwright/test

/**
 * @see https://playwright.dev/docs/test-configuration
 */
module.exports = {
  testDir: './tests/e2e',
  fullyParallel: false, // WordPress tests should run sequentially
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Single worker for WordPress to avoid conflicts
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:8889',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        channel: 'chrome',
      },
    },
  ],

  webServer: {
    command: 'npx @wordpress/env start',
    url: 'http://localhost:8889',
    reuseExistingServer: true,
    timeout: 120 * 1000,
  },
};