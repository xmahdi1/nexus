import { createRequire } from 'node:module';

// Resolve the pinned browser tooling from the application's development install.
// No maintainer-specific absolute path or globally installed browser is required.
const require = createRequire(new URL('../nexus-vue/package.json', import.meta.url));
const { chromium } = require('playwright');

export function launchBrowser() {
  const target = process.env.NEXUS_LAB_URL;
  if (!target || new URL(target).hostname !== '127.0.0.1')
    throw new Error('An owned loopback fixture is required');
  return chromium.launch({
    headless: true,
    executablePath: process.env.NEXUS_BROWSER_EXECUTABLE || undefined,
    chromiumSandbox: process.env.NEXUS_BROWSER_SANDBOX !== 'false',
  });
}
