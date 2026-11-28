import { launchBrowser } from './browser_tools.mjs';
import assert from 'node:assert/strict';
const url = process.env.NEXUS_LAB_URL,
  password = process.env.NEXUS_LAB_PASSWORD,
  repository = process.env.NEXUS_LAB_BACKUP_REPOSITORY;
if (!url || new URL(url).hostname !== '127.0.0.1' || !password || !repository)
  throw new Error('Owned loopback fixture required');
const browser = await launchBrowser();
try {
  const context = await browser.newContext({ serviceWorkers: 'block' }),
    page = await context.newPage(),
    errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(url + '/login');
  await page.getByLabel('Username', { exact: true }).fill('owner');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL('**/dashboard');
  await page.route('**/api/features', async (route) => {
    const response = await route.fetch();
    return route.fulfill({ response, json: { ...(await response.json()), operationSupervision: true } });
  });
  await page.goto(url + '/backups');
  await page
    .getByRole('heading', { name: 'Backups', exact: true })
    .waitFor()
    .catch(async (error) => {
      console.error('Backup page failed:', page.url(), await page.locator('body').innerText(), errors);
      throw error;
    });
  await page.getByLabel('Backup target', { exact: true }).selectOption('nexus');
  let workspace = page.getByRole('region', { name: 'Backup workspace', exact: true });
  await workspace.getByRole('button', { name: 'Set up a backup', exact: true }).click();
  await workspace.getByRole('button', { name: 'Detect backup sources', exact: true }).click();
  await workspace
    .getByRole('checkbox', { name: /Nexus database, matching key and recovery metadata/ })
    .check();
  await workspace.getByRole('button', { name: 'Continue setup', exact: true }).click();
  await workspace.getByLabel('Repository location', { exact: true }).fill(repository);
  await workspace.getByLabel('Repository password', { exact: true }).fill('browser-only-repository-password');
  await workspace.getByRole('button', { name: 'Continue setup', exact: true }).click();
  await workspace.getByLabel('Backup timing', { exact: true }).selectOption('once');
  const later = new Date(Date.now() + 3600000);
  later.setMinutes(later.getMinutes() - later.getTimezoneOffset());
  await workspace.getByLabel('Run once at', { exact: true }).fill(later.toISOString().slice(0, 16));
  await workspace.getByRole('button', { name: 'Continue setup', exact: true }).click();
  await workspace.getByLabel('Backup name', { exact: true }).fill('Browser Nexus recovery');
  await workspace.getByRole('button', { name: 'Save backup policy', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Save this backup policy?', exact: true })
    .getByRole('button', { name: 'Save backup policy', exact: true })
    .click();
  await workspace.getByRole('heading', { name: 'Browser Nexus recovery', exact: true }).waitFor();
  assert.equal(
    await workspace.getByRole('button', { name: 'Enable schedule', exact: true }).isDisabled(),
    true,
  );
  const policiesResponse = await context.request.get(url + '/api/backups/nexus/policies'),
    policies = await policiesResponse.json();
  assert.equal(policiesResponse.status(), 200);
  assert.equal(policies.length, 1);
  assert.equal(policies[0].mode, 'once');
  assert.equal(policies[0].enabled, false);
  assert.equal(JSON.stringify(policies).includes('browser-only-repository-password'), false);
  assert.equal(
    (await (await context.request.get(url + '/api/backups/nexus/runs')).json()).length,
    0,
    'wizard unexpectedly ran a backup',
  );
  let saved = null,
    submissions = 0,
    run = null,
    coverage = null,
    cleanupCalls = 0,
    previewRun = '';
  let managementSettings = { keepLast: 7, maxAgeMinutes: 0, verifyAfterDays: 30 };
  const candidate = {
    id: 'a'.repeat(64),
    source: { kind: 'files', path: '/srv/fixture', label: 'Fixture application' },
    state: 'ready',
    consistency: 'File copy; live writes may be inconsistent',
    note: '',
  };
  await page.route('**/api/servers/controller/backups/**', (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (path.endsWith('/health'))
      return route.fulfill({
        json: {
          observedAt: new Date().toISOString(),
          policies: saved
            ? [
                {
                  policyId: saved.id,
                  name: saved.name,
                  state: saved.lastState,
                  settings: managementSettings,
                  issues: [],
                },
              ]
            : [],
          alerts: [],
          coverage,
        },
      });
    if (path.endsWith('/settings')) {
      assert.equal(request.method(), 'PUT');
      managementSettings = request.postDataJSON();
      assert.equal(managementSettings.keepLast, 2);
      return route.fulfill({ status: 204 });
    }
    if (path.endsWith('/coverage')) {
      coverage = {
        scannedAt: new Date().toISOString(),
        truncated: false,
        watchGaps: request.postDataJSON().watchGaps,
        items: [{ candidate, state: 'configured', policyIds: [saved.id] }],
      };
      return route.fulfill({ json: coverage });
    }
    if (path.endsWith('/discover'))
      return route.fulfill({
        json: {
          sources: [
            candidate,
            {
              ...candidate,
              id: 'b'.repeat(64),
              source: { kind: 'docker-volume', volume: 'plugin', label: 'Unsupported plugin' },
              state: 'unsupported',
            },
          ],
          tools: { docker: true },
          truncated: false,
        },
      });
    if (path.endsWith('/policies') && request.method() === 'POST') {
      submissions++;
      const input = request.postDataJSON();
      assert.equal(input.definition.sources.length, 2);
      assert.equal(input.definition.sources[0].path, '/srv/fixture');
      assert.equal(input.definition.sources[1].kind, 'postgres');
      assert.equal(input.definition.repository.kind, 's3');
      assert.equal(input.definition.timing.mode, 'interval');
      assert.equal(input.definition.timing.intervalMinutes, 1440);
      saved = {
        id: input.requestId,
        serverId: 'controller',
        name: input.definition.name,
        repository: { kind: 's3', location: input.definition.repository.location },
        sources: input.definition.sources.map(({ database, ...s }) => s),
        sourceKinds: ['files', 'postgres'],
        mode: 'interval',
        enabled: false,
        archived: false,
        lastState: 'setup_required',
        createdAt: new Date().toISOString(),
      };
      return route.fulfill({ status: 201, json: saved });
    }
    if (path.endsWith('/policies')) return route.fulfill({ json: saved ? [saved] : [] });
    if (path.endsWith('/runs') && request.method() === 'POST') {
      const input = request.postDataJSON();
      assert.ok(['snapshots', 'retention-preview', 'retention-apply'].includes(input.action));
      if (input.action === 'retention-preview') previewRun = input.requestId;
      if (input.action === 'retention-apply') {
        cleanupCalls++;
        assert.equal(input.previewRunId, previewRun);
      }
      run = {
        id: input.requestId,
        policyId: saved.id,
        action: 'backup:' + input.action,
        state: 'exited',
        createdAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        artifactsRemoved: true,
        stagingClean: true,
      };
      return route.fulfill({ status: 202, json: run });
    }
    if (path.endsWith('/inspect'))
      return route.fulfill({
        json: {
          run,
          observation: { state: 'exited' },
          result:
            run.action === 'backup:retention-preview'
              ? {
                  state: 'retention_preview',
                  verified: true,
                  retention: {
                    keepLast: 2,
                    inventoryDigest: 'd'.repeat(64),
                    removeIds: ['e'.repeat(64)],
                    keptCount: 2,
                    unclassifiedCount: 0,
                  },
                }
              : {
                  state: 'snapshots',
                  verified: false,
                  snapshots: [{ id: 'c'.repeat(64), time: new Date().toISOString() }],
                },
          automaticRetryAllowed: false,
        },
      });
    if (path.endsWith('/runs')) return route.fulfill({ json: run ? [run] : [] });
    throw new Error('Unexpected backup request ' + path);
  });
  await page.getByLabel('Backup target', { exact: true }).selectOption('controller');
  await workspace.getByRole('button', { name: 'Set up a backup', exact: true }).click();
  await workspace.getByRole('button', { name: 'Detect backup sources', exact: true }).click();
  assert.equal(await workspace.getByRole('checkbox', { name: /Unsupported plugin/ }).isDisabled(), true);
  await workspace.getByRole('checkbox', { name: /Fixture application/ }).check();
  await workspace.getByLabel('Manual source type', { exact: true }).selectOption('postgres');
  await workspace.getByRole('button', { name: 'Add manual source', exact: true }).click();
  await workspace.getByRole('checkbox', { name: /I understand file and volume copies/ }).check();
  await workspace.getByRole('button', { name: 'Continue setup', exact: true }).click();
  await workspace.getByLabel('Repository type', { exact: true }).selectOption('s3');
  await workspace
    .getByLabel('Repository location', { exact: true })
    .fill('s3:https://storage.example.test/bucket/fixture');
  for (const label of ['Repository password', 'S3 access key', 'S3 secret key', 'Session token (optional)'])
    await workspace.getByLabel(label, { exact: true }).fill('browser-secret-to-clear');
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { value: true, configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
  });
  for (const label of ['Repository password', 'S3 access key', 'S3 secret key', 'Session token (optional)'])
    assert.equal(await workspace.getByLabel(label, { exact: true }).inputValue(), '');
  for (const label of ['Repository password', 'S3 access key', 'S3 secret key'])
    await workspace.getByLabel(label, { exact: true }).fill('browser-fixture-private');
  await workspace.getByRole('button', { name: 'Continue setup', exact: true }).click();
  await workspace.getByLabel('Backup timing', { exact: true }).selectOption('interval');
  await workspace.getByRole('button', { name: 'Continue setup', exact: true }).click();
  await workspace.getByLabel('Backup name', { exact: true }).fill('Browser server sources');
  await workspace.getByRole('button', { name: 'Save backup policy', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Save this backup policy?', exact: true })
    .getByRole('button', { name: 'Save backup policy', exact: true })
    .click();
  await workspace.getByRole('heading', { name: 'Browser server sources', exact: true }).waitFor();
  assert.equal(submissions, 1);
  assert.equal(await page.locator('input[type=password]').count(), 0);
  await workspace.getByRole('button', { name: 'List snapshots', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Start backup operation?', exact: true })
    .getByRole('button', { name: 'Start operation', exact: true })
    .click();
  await workspace.getByRole('button', { name: 'Inspect backup run', exact: true }).click();
  await workspace.getByLabel('Snapshot to restore', { exact: true }).selectOption('c'.repeat(64));
  assert.equal(
    await workspace.getByRole('button', { name: 'Restore a copy', exact: true }).isEnabled(),
    true,
  );
  await workspace.getByRole('button', { name: 'Restore a copy', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Restore a backup copy?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  const management = page.getByRole('region', { name: 'Backup health and retention', exact: true });
  await management.getByRole('button', { name: 'Refresh backup health', exact: true }).click();
  await management.getByText('Source coverage', { exact: true }).click();
  await management.getByRole('button', { name: 'Refresh source coverage', exact: true }).click();
  await management.getByText(/Fixture application · files · configured/).waitFor();
  await management.getByText('Retention and health settings', { exact: true }).click();
  await management.getByLabel('Keep latest successful snapshots', { exact: true }).fill('2');
  await management.getByRole('button', { name: 'Save management settings', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Save backup management settings?', exact: true })
    .getByRole('button', { name: 'Save settings', exact: true })
    .click();
  await management
    .getByText('Settings saved. Create a fresh retention preview before cleanup.', { exact: true })
    .waitFor();
  await management.getByRole('button', { name: 'Preview retention', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Preview backup retention?', exact: true })
    .getByRole('button', { name: 'Preview retention', exact: true })
    .click();
  await workspace.getByRole('button', { name: 'Inspect backup run', exact: true }).click();
  await management.getByText(/Preview: 1 to remove/).waitFor();
  await management.getByRole('button', { name: 'Apply retention preview', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Remove previewed snapshots?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(cleanupCalls, 0);
  await management.getByRole('button', { name: 'Apply retention preview', exact: true }).click();
  await page
    .getByRole('alertdialog', { name: 'Remove previewed snapshots?', exact: true })
    .getByRole('button', { name: 'Remove snapshots', exact: true })
    .click();
  await management.getByText(/Operation saved. Refresh run history/).waitFor();
  assert.equal(cleanupCalls, 1);
  assert.equal(
    await page.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }).includes('browser-fixture-private'),
    ),
    false,
  );
  assert.deepEqual(errors, []);
  console.log(
    'Chrome backups passed: real policy save/discovery, one-time timing, source selection, S3 secret clearing, history/restore, coverage/settings and retention preview/cancel/exact application.',
  );
} finally {
  await browser.close();
}
