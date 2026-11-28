import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { launchBrowser } from './browser_tools.mjs';

const url = process.env.NEXUS_LAB_URL;
const output = process.argv[2];
const frames = mkdtempSync(join(tmpdir(), 'nexus-demo-frames-'));
const browser = await launchBrowser();
try {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 840 },
    colorScheme: 'dark',
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });
  await context.route('**/*', (route) =>
    route
      .request()
      .url()
      .startsWith(url + '/')
      ? route.continue()
      : route.abort(),
  );
  const page = await context.newPage();
  await page.goto(url + '/login');
  await page.getByLabel('Username', { exact: true }).fill('demo');
  await page.getByLabel('Password', { exact: true }).fill(process.env.NEXUS_LAB_PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL('**/dashboard');
  await page.getByText('Edge gateway', { exact: true }).first().waitFor();

  for (const [method, path] of [
    ['POST', '/api/servers'],
    ['GET', '/api/servers/edge/files'],
    ['GET', '/ws/terminal/edge'],
  ]) {
    const response = await context.request.fetch(url + path, { method });
    assert.equal(response.status(), 403, path);
  }

  await page.screenshot({ path: join(output, 'dashboard.png') });
  await page.screenshot({ path: join(frames, 'frame-01.png') });
  await page.getByRole('link', { name: 'Servers', exact: true }).click();
  await page.getByText('Build host', { exact: true }).first().waitFor();
  await page.screenshot({ path: join(frames, 'frame-02.png') });
  await page.getByRole('link', { name: 'Services', exact: true }).click();
  const services = await context.request.get(url + '/api/services');
  assert.equal(services.status(), 200);
  assert.ok((await services.json()).some(({ name }) => name === 'Grafana'));
  await page.getByText('Grafana', { exact: true }).waitFor();
  await page.screenshot({ path: join(frames, 'frame-03.png') });
  execFileSync('ffmpeg', [
    '-hide_banner',
    '-loglevel',
    'error',
    '-y',
    '-framerate',
    '1/2',
    '-i',
    join(frames, 'frame-%02d.png'),
    '-vf',
    'scale=960:-1:flags=lanczos',
    '-loop',
    '0',
    join(output, 'navigation.gif'),
  ]);
} finally {
  await browser.close();
  rmSync(frames, { recursive: true, force: true });
}
