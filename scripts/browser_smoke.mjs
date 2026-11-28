import { launchBrowser } from './browser_tools.mjs';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
const url = process.env.NEXUS_LAB_URL,
  password = process.env.NEXUS_LAB_PASSWORD;
if (!url || new URL(url).hostname !== '127.0.0.1' || !password)
  throw new Error('Temporary loopback fixture required');
function otp(secret) {
  let bits = '';
  for (const char of secret)
    bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
  const offset = hash.at(-1) & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}
const browser = await launchBrowser();
try {
  const owner = await browser.newContext({ serviceWorkers: 'block' }),
    viewer = await browser.newContext({ serviceWorkers: 'block' });
  const ownerPage = await owner.newPage(),
    viewerPage = await viewer.newPage();
  async function api(context, path, data, method = 'POST') {
    const response = await context.request.fetch(url + '/api' + path, {
      method,
      headers: { Origin: url },
      data,
    });
    return response;
  }
  async function login(page, name, code) {
    await page.goto(url + '/login');
    await page.getByLabel('Username', { exact: true }).fill(name);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    if (code) {
      await page.getByRole('button', { name: 'Use a recovery code', exact: true }).click();
      await page.getByLabel('Recovery code', { exact: true }).fill(code);
      await page.getByRole('button', { name: 'Verify', exact: true }).click();
    }
    await page.waitForURL('**/dashboard', { timeout: 10000 });
  }
  async function enroll(context) {
    const setup = await api(context, '/auth/mfa/setup', { currentPassword: password });
    assert.equal(setup.status(), 200);
    const enrollment = await setup.json();
    const response = await api(context, '/auth/mfa/enable', {
      setupToken: enrollment.setupToken,
      code: otp(enrollment.secret),
    });
    assert.equal(response.status(), 200);
    const result = await response.json();
    assert.equal(result.recoveryCodes.length, 10);
    return result.recoveryCodes;
  }
  await login(ownerPage, 'owner');
  await ownerPage.route('**/api/features', (route) =>
    route.fulfill({
      status: 200,
      json: {
        automation: true,
        inventory: true,
        jobSupervision: true,
        vault: true,
        operationSupervision: true,
      },
    }),
  );
  // GitHub metadata is real; provider calls are isolated UI fixtures.
  let providerRemoves = 0,
    workflowChanges = 0;
  let githubDispatches = 0,
    githubCancellations = 0,
    githubLogReads = 0,
    githubArtifactDownloads = 0;
  const githubConnection = 'd'.repeat(32);
  await ownerPage.route('**/api/servers/controller/github/connections/*/workflows**', (route) =>
    route.fulfill({
      status: 200,
      json: {
        total_count: 1,
        workflows: [
          { id: 7, name: 'Fixture workflow', path: '.github/workflows/build.yml', state: 'active' },
          {
            id: 8,
            name: 'Disabled workflow',
            path: '.github/workflows/paused.yml',
            state: 'disabled_manually',
          },
        ],
      },
    }),
  );
  await ownerPage.route('**/api/servers/controller/github/connections/*/dispatch', (route) => {
    githubDispatches++;
    const body = route.request().postDataJSON();
    assert.equal(body.workflowId, 7);
    assert.equal(body.ref, 'main');
    assert.deepEqual(body.inputs, { enabled: true });
    return route.fulfill({
      status: 202,
      json: {
        submission: {
          id: body.requestId,
          connectionId: githubConnection,
          state: 'submitted',
          workflowId: 7,
          ref: 'main',
          runId: 99,
          createdAt: new Date().toISOString(),
        },
        automaticRetryAllowed: false,
      },
    });
  });
  const githubRun = {
    id: 99,
    workflow_id: 7,
    run_attempt: 1,
    status: 'in_progress',
    conclusion: null,
    head_sha: 'a'.repeat(40),
    head_branch: 'main',
    event: 'workflow_dispatch',
  };
  await ownerPage.route('**/api/servers/controller/github/connections/*/runs**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/logs')) {
      githubLogReads++;
      return route.fulfill({
        status: 200,
        json: { content: '<script>fixture log text</script>', runId: 99, jobId: 101, redacted: false },
      });
    }
    if (path.endsWith('/cancel')) {
      githubCancellations++;
      const body = route.request().postDataJSON();
      assert.equal(body.runAttempt, 1);
      return route.fulfill({
        status: 202,
        json: {
          cancellation: {
            id: body.requestId,
            connectionId: githubConnection,
            runId: 99,
            runAttempt: 1,
            state: 'requested',
          },
          automaticRetryAllowed: false,
        },
      });
    }
    if (path.endsWith('/download')) {
      githubArtifactDownloads++;
      return route.fulfill({
        status: 200,
        contentType: 'application/zip',
        body: Buffer.from('504b0506000000000000000000000000000000000000', 'hex'),
      });
    }
    if (path.endsWith('/artifacts'))
      return route.fulfill({
        status: 200,
        json: {
          total_count: 1,
          artifacts: [
            {
              id: 5,
              name: 'Fixture artifact',
              size_in_bytes: 22,
              expired: false,
              workflow_run: { id: 99, repository_id: 123 },
            },
          ],
        },
      });
    if (path.endsWith('/jobs'))
      return route.fulfill({
        status: 200,
        json: {
          total_count: 1,
          jobs: [{ id: 101, run_id: 99, name: 'Build job', status: 'completed', conclusion: 'success' }],
        },
      });
    return route.fulfill({
      status: 200,
      json: path.endsWith('/runs/99') ? githubRun : { total_count: 1, workflow_runs: [githubRun] },
    });
  });
  await ownerPage.route('**/api/servers/controller/github/connections/*/provider-runners**', (route) => {
    if (new URL(route.request().url()).pathname.endsWith('/remove')) {
      providerRemoves++;
      const body = route.request().postDataJSON();
      assert.equal(body.runnerId, 9);
      assert.equal(body.name, 'offline-fixture');
      return route.fulfill({
        status: 202,
        json: {
          change: {
            id: body.requestId,
            connectionId: githubConnection,
            kind: 'runner_remove',
            state: 'applied',
            resourceId: 9,
          },
          automaticRetryAllowed: false,
        },
      });
    }
    return route.fulfill({
      status: 200,
      json: {
        total_count: 2,
        runners: [
          {
            id: 9,
            name: 'offline-fixture',
            os: 'linux',
            status: 'offline',
            busy: false,
            ephemeral: true,
            version: 'fixture',
            labels: [],
          },
          {
            id: 10,
            name: 'online-fixture',
            os: 'linux',
            status: 'online',
            busy: true,
            ephemeral: false,
            version: 'fixture',
            labels: [],
          },
        ],
      },
    });
  });
  const workflowFile = {
    baseBranch: 'main',
    baseSha: 'a'.repeat(40),
    blobSha: 'b'.repeat(40),
    path: '.github/workflows/build.yml',
    content: 'name: Fixture\non: [workflow_dispatch]\njobs: {}\n',
  };
  await ownerPage.route('**/api/servers/controller/github/connections/*/workflow-file', (route) =>
    route.fulfill({ status: 200, json: workflowFile }),
  );
  await ownerPage.route('**/api/servers/controller/github/connections/*/workflow-change', (route) => {
    workflowChanges++;
    const body = route.request().postDataJSON();
    assert.equal(body.baseSha, workflowFile.baseSha);
    assert.equal(body.blobSha, workflowFile.blobSha);
    assert.match(body.content, /name: Updated/);
    return route.fulfill({
      status: 202,
      json: {
        change: {
          id: body.requestId,
          connectionId: githubConnection,
          kind: 'workflow_edit',
          state: 'applied',
          phase: 'pull_create',
          branch: 'nexus/workflows/' + body.requestId,
          commitSha: 'c'.repeat(40),
          pullNumber: 42,
        },
        automaticRetryAllowed: false,
      },
    });
  });
  await ownerPage.goto(url + '/automation');
  await ownerPage.getByLabel('GitHub permission scope', { exact: true }).selectOption('controller');
  const githubPanel = ownerPage.getByRole('region', { name: 'GitHub repository connection', exact: true });
  await githubPanel.getByLabel('GitHub connection', { exact: true }).selectOption(githubConnection);
  // Real local signed intake, with no GitHub delivery or external credentials.
  const webhookPanel = githubPanel.getByRole('region', { name: 'GitHub webhook updates', exact: true });
  await webhookPanel.getByText('Webhook setup', { exact: true }).click();
  await webhookPanel.getByRole('button', { name: 'Create new webhook secret', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Create a new webhook secret?', exact: true })
    .getByRole('button', { name: 'Create secret', exact: true })
    .click();
  const hookInput = webhookPanel.getByLabel('One-time webhook secret', { exact: true });
  await hookInput.waitFor();
  const hookSecret = await hookInput.inputValue(),
    hookPath = await webhookPanel.getByLabel('Webhook endpoint path', { exact: true }).inputValue();
  const hookBody = JSON.stringify({
    action: 'completed',
    repository: { id: 123, full_name: 'fixture/repository' },
    workflow_run: {
      id: 299,
      workflow_id: 7,
      run_attempt: 1,
      status: 'completed',
      conclusion: 'success',
      head_sha: 'a'.repeat(40),
      updated_at: new Date().toISOString(),
    },
  });
  const hookHeaders = {
    'Content-Type': 'application/json',
    'X-GitHub-Event': 'workflow_run',
    'X-GitHub-Delivery': '01020304-1234-1234-1234-0123456789ab',
    'X-Hub-Signature-256': 'sha256=' + createHmac('sha256', hookSecret).update(hookBody).digest('hex'),
  };
  const received = await owner.request.post(url + hookPath, { headers: hookHeaders, data: hookBody });
  assert.equal(received.status(), 202);
  assert.equal(
    (
      await (
        await owner.request.post(url + hookPath, {
          headers: { ...hookHeaders, 'X-GitHub-Delivery': '01020304-1234-1234-1234-0123456789ac' },
          data: hookBody,
        })
      ).json()
    ).duplicate,
    true,
  );
  await webhookPanel.getByRole('button', { name: 'Refresh received status', exact: true }).click();
  await webhookPanel.getByText('Run 299 · attempt 1 · completed / success', { exact: true }).waitFor();
  await webhookPanel.getByRole('button', { name: 'Disable intake', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Disable webhook intake?', exact: true })
    .getByRole('button', { name: 'Disable', exact: true })
    .click();
  await webhookPanel.getByText('Intake disabled', { exact: true }).waitFor();
  assert.equal(await hookInput.count(), 0, 'disabled intake retained the disclosed secret');
  assert.equal(
    (await owner.request.post(url + hookPath, { headers: hookHeaders, data: hookBody })).status(),
    401,
  );

  let orgRemoves = 0,
    orgRegistrations = 0;
  await ownerPage.route('**/api/servers/controller/github/organizations/*/runners**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/remove')) {
      orgRemoves++;
      const input = route.request().postDataJSON();
      return route.fulfill({
        status: 202,
        json: {
          change: {
            id: input.requestId,
            connectionId: 'e'.repeat(32),
            kind: 'runner_remove',
            state: 'applied',
            resourceId: 19,
          },
          credential: null,
          automaticRetryAllowed: false,
        },
      });
    }
    return route.fulfill({
      status: 200,
      json: {
        total_count: 2,
        runners: [
          {
            id: 19,
            name: 'old-org-runner',
            os: 'linux',
            status: 'offline',
            busy: false,
            ephemeral: true,
            version: 'fixture',
            labels: [],
          },
          {
            id: 20,
            name: 'busy-org-runner',
            os: 'linux',
            status: 'online',
            busy: true,
            ephemeral: true,
            version: 'fixture',
            labels: [],
          },
        ],
      },
    });
  });
  await ownerPage.route('**/api/servers/controller/github/organizations/*/registration-token', (route) => {
    orgRegistrations++;
    const input = route.request().postDataJSON();
    return route.fulfill({
      status: 202,
      json: {
        change: {
          id: input.requestId,
          connectionId: 'e'.repeat(32),
          kind: 'registration',
          state: 'applied',
          resourceId: 0,
        },
        credential: {
          token: 'REGISTRATION_BROWSER_FIXTURE',
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        },
        automaticRetryAllowed: false,
      },
    });
  });
  const orgPanel = ownerPage.getByRole('region', { name: 'GitHub organization runners', exact: true });
  await orgPanel.getByLabel('GitHub organization connection', { exact: true }).selectOption('e'.repeat(32));
  await orgPanel.getByRole('button', { name: 'List organization runners', exact: true }).click();
  const offlineOrg = orgPanel.getByRole('listitem').filter({ hasText: 'old-org-runner' }),
    busyOrg = orgPanel.getByRole('listitem').filter({ hasText: 'busy-org-runner' });
  assert.equal(
    await busyOrg.getByRole('button', { name: 'Remove offline registration', exact: true }).isDisabled(),
    true,
  );
  await offlineOrg.getByRole('button', { name: 'Remove offline registration', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Remove organization runner?', exact: true })
    .getByRole('button', { name: 'Remove registration', exact: true })
    .click();
  await offlineOrg.waitFor({ state: 'detached' });
  assert.equal(orgRemoves, 1);
  await orgPanel.getByRole('button', { name: 'Create registration token', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Create runner registration token?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(orgRegistrations, 0);
  await orgPanel.getByRole('button', { name: 'Create registration token', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Create runner registration token?', exact: true })
    .getByRole('button', { name: 'Create token once', exact: true })
    .click();
  await orgPanel.getByLabel('One-time runner registration token', { exact: true }).waitFor();
  assert.equal(
    await orgPanel.getByLabel('One-time runner registration token', { exact: true }).inputValue(),
    'REGISTRATION_BROWSER_FIXTURE',
  );
  await orgPanel.getByRole('button', { name: 'Clear token', exact: true }).click();
  assert.equal(await orgPanel.getByLabel('One-time runner registration token', { exact: true }).count(), 0);
  assert.equal(orgRegistrations, 1);
  await ownerPage.unroute('**/api/servers/controller/github/organizations/*/runners**');
  await ownerPage.unroute('**/api/servers/controller/github/organizations/*/registration-token');

  await githubPanel.getByRole('button', { name: 'List workflows', exact: true }).click();
  await githubPanel.getByLabel('GitHub workflow', { exact: true }).selectOption('8');
  await githubPanel.getByRole('button', { name: 'Review workflow YAML', exact: true }).waitFor();
  assert.equal(
    await githubPanel.getByRole('button', { name: 'Dispatch selected workflow', exact: true }).count(),
    0,
    'disabled workflows may be edited but not dispatched',
  );
  await githubPanel.getByLabel('GitHub workflow', { exact: true }).selectOption('7');
  const repositoryRunners = githubPanel.getByRole('region', {
    name: 'GitHub repository runners',
    exact: true,
  });
  await repositoryRunners.getByText('Registration 9 · offline-fixture · linux', { exact: true }).waitFor();
  assert.equal(
    await repositoryRunners.getByRole('button', { name: 'Remove registration 10', exact: true }).isDisabled(),
    true,
  );
  await repositoryRunners.getByRole('button', { name: 'Remove registration 9', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Remove GitHub runner registration?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(providerRemoves, 0);
  await repositoryRunners.getByRole('button', { name: 'Remove registration 9', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Remove GitHub runner registration?', exact: true })
    .getByRole('button', { name: 'Remove registration', exact: true })
    .click();
  await repositoryRunners.getByText(/registration 9 · applied/).waitFor();
  assert.equal(providerRemoves, 1);
  await githubPanel.getByRole('button', { name: 'Review workflow YAML', exact: true }).click();
  const workflowEditor = githubPanel.getByRole('region', { name: 'GitHub workflow editor', exact: true });
  await workflowEditor.getByRole('button', { name: 'Open workflow', exact: true }).click();
  await workflowEditor
    .getByRole('textbox', { name: 'Workflow YAML content', exact: true })
    .fill('name: Updated\non: [workflow_dispatch]\njobs: {}\n');
  await workflowEditor.getByLabel('Pull request title', { exact: true }).fill('Update fixture workflow');
  await workflowEditor.getByLabel('Workflow diff', { exact: true }).waitFor();
  assert.match(
    await workflowEditor.getByLabel('Workflow diff', { exact: true }).textContent(),
    /\+name: Updated/,
  );
  assert.equal(
    await workflowEditor.getByRole('button', { name: 'Create draft PR', exact: true }).isDisabled(),
    true,
  );
  await workflowEditor
    .getByRole('checkbox', { name: 'I reviewed this workflow diff and title', exact: true })
    .check();
  await workflowEditor.getByRole('button', { name: 'Create draft PR', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Create workflow draft PR?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(workflowChanges, 0);
  await workflowEditor.getByRole('button', { name: 'Create draft PR', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Create workflow draft PR?', exact: true })
    .getByRole('button', { name: 'Create draft PR', exact: true })
    .click();
  await workflowEditor.getByRole('link', { name: 'Open draft PR 42', exact: true }).waitFor();
  assert.equal(workflowChanges, 1);

  await githubPanel.getByLabel('Workflow inputs (JSON)', { exact: true }).fill('{"enabled":true}');
  await githubPanel.getByRole('button', { name: 'Dispatch selected workflow', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Dispatch GitHub workflow?', exact: true })
    .getByRole('button', { name: 'Dispatch once', exact: true })
    .click();
  await githubPanel.getByText(/GitHub run 99/).waitFor();
  assert.equal(githubDispatches, 1);
  await githubPanel.getByRole('button', { name: 'List workflow runs', exact: true }).click();
  await githubPanel.getByRole('button', { name: 'Inspect jobs', exact: true }).click();
  await githubPanel.getByText('Build job · completed · success', { exact: true }).waitFor();
  assert.equal(githubDispatches, 1);
  const runDetails = githubPanel.getByRole('region', { name: 'GitHub run details', exact: true });
  await runDetails.getByRole('button', { name: 'Read logs for job 101', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Read raw workflow logs?', exact: true })
    .getByRole('button', { name: 'Read logs', exact: true })
    .click();
  await runDetails.getByText('<script>fixture log text</script>', { exact: true }).waitFor();
  assert.equal(githubLogReads, 1);
  await runDetails.getByRole('button', { name: 'Hide workflow logs', exact: true }).click();
  await runDetails.getByRole('button', { name: 'List artifacts', exact: true }).click();
  await runDetails.getByRole('button', { name: 'Download artifact 5', exact: true }).click();
  const downloadEvent = ownerPage.waitForEvent('download');
  await ownerPage
    .getByRole('alertdialog', { name: 'Download workflow artifact?', exact: true })
    .getByRole('button', { name: 'Download ZIP', exact: true })
    .click();
  const artifact = await downloadEvent;
  assert.equal(artifact.suggestedFilename(), 'github-artifact-5.zip');
  assert.equal(githubArtifactDownloads, 1);
  await runDetails.getByRole('button', { name: 'Request cancellation', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Request workflow cancellation?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(githubCancellations, 0);
  await runDetails.getByRole('button', { name: 'Request cancellation', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Request workflow cancellation?', exact: true })
    .getByRole('button', { name: 'Request cancellation', exact: true })
    .click();
  await runDetails
    .getByText('GitHub accepted the cancellation request. Refresh status to check completion.', {
      exact: true,
    })
    .waitFor();
  assert.equal(githubCancellations, 1);

  await ownerPage.unroute('**/api/servers/controller/github/connections/*/provider-runners**');
  await ownerPage.unroute('**/api/servers/controller/github/connections/*/workflow-file');
  await ownerPage.unroute('**/api/servers/controller/github/connections/*/workflow-change');
  await ownerPage.unroute('**/api/servers/controller/github/connections/*/workflows**');
  await ownerPage.unroute('**/api/servers/controller/github/connections/*/dispatch');
  await ownerPage.unroute('**/api/servers/controller/github/connections/*/runs**');
  // Real inventory preview; explicit grants include dev but exclude prod in the
  // same automation group. Environment submission below is a UI-only fixture.
  await ownerPage.goto(url + '/automation');
  await ownerPage.getByRole('heading', { name: 'Dynamic inventory', exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Preview current targets', exact: true }).click();
  await ownerPage.getByRole('cell', { name: 'dev', exact: true }).waitFor();
  assert.equal(await ownerPage.getByRole('cell', { name: 'prod', exact: true }).count(), 0);
  assert.equal(await ownerPage.getByLabel('Copy once into a private token file (mode 0600)').count(), 0);

  // Explicit controller selection; real encrypted project/revision API with a
  // fake plan-admission response. Preparing a Vault reference never retrieves it.
  await ownerPage.getByLabel('Ansible controller', { exact: true }).selectOption('controller');
  const projectsPanel = ownerPage.getByRole('region', { name: 'Playbook project workspace', exact: true });
  await projectsPanel.getByPlaceholder('New project name', { exact: true }).fill('Browser playbooks');
  await projectsPanel.getByRole('button', { name: 'Create project', exact: true }).click();
  await projectsPanel.getByText('Playbook editor', { exact: true }).waitFor();
  const helpers = projectsPanel.getByRole('region', { name: 'Ansible project helpers', exact: true });
  await helpers.getByText('Reusable project templates', { exact: true }).click();
  await helpers.getByPlaceholder('Template name', { exact: true }).fill('Reusable browser playbook');
  await helpers.getByRole('button', { name: 'Save current draft as template', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Save a reusable project template?', exact: true })
    .getByRole('button', { name: 'Save template', exact: true })
    .click();
  await helpers
    .getByText('Template saved. Each use still needs a revision and an independently approved target plan.', {
      exact: true,
    })
    .waitFor();
  const savedTemplates = await (
    await api(owner, '/servers/controller/ansible/templates', undefined, 'GET')
  ).json();
  assert.equal(savedTemplates.length, 1);
  await helpers.getByLabel('Ansible project template', { exact: true }).selectOption(savedTemplates[0].id);
  await projectsPanel
    .getByLabel('File content', { exact: true })
    .fill('- hosts: all\n  tasks:\n    - shell: echo fixture-only\n');
  await helpers.getByText(/Project checks ·/).click();
  await helpers.getByText(/Review command execution/).waitFor();
  await helpers.getByRole('button', { name: 'Reveal and load template', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Load template content?', exact: true })
    .getByRole('button', { name: 'Load template', exact: true })
    .click();
  await projectsPanel
    .getByText('Template loaded as a draft. Publish and review a new revision before planning.', {
      exact: true,
    })
    .waitFor();
  assert.match(
    await projectsPanel.getByLabel('File content', { exact: true }).inputValue(),
    /ansible.builtin.ping/,
  );

  await projectsPanel
    .getByLabel('File content', { exact: true })
    .fill('---\n- hosts: all\n  gather_facts: false\n  tasks: []\n');
  const publishedRevisionResponse = ownerPage.waitForResponse(
    (response) =>
      response.url().includes('/servers/controller/ansible/projects/') &&
      response.url().endsWith('/revisions') &&
      response.request().method() === 'POST',
  );
  await projectsPanel.getByRole('button', { name: 'Publish new revision', exact: true }).click();
  const publishedRevision = await (await publishedRevisionResponse).json();
  await projectsPanel
    .getByRole('combobox', { name: 'Automation group', exact: true })
    .selectOption('automation');
  await projectsPanel.getByRole('button', { name: 'Preview eligible targets', exact: true }).click();
  await projectsPanel.getByRole('checkbox', { name: /dev · fixture@/ }).check();
  await projectsPanel
    .getByRole('checkbox', { name: 'Use Vault for the Ansible Vault password', exact: true })
    .check();
  await projectsPanel.getByLabel('Vault server', { exact: true }).selectOption('dev');
  await projectsPanel.getByLabel('Secret path', { exact: true }).fill('automation/project');
  const projectIdentity = await (await api(owner, '/auth/me', undefined, 'GET')).json();
  let preparedPlan,
    vaultCalls = 0;
  await ownerPage.route('**/api/servers/*/vault**', (route) => {
    vaultCalls++;
    return route.continue();
  });
  await ownerPage.route('**/api/servers/controller/ansible/projects/*/plans', (route) => {
    const body = route.request().postDataJSON();
    assert.deepEqual(body.serverIds, ['dev']);
    assert.equal(body.options.mode, 'check');
    assert.deepEqual(body.options.vaultPassword, {
      serverId: 'dev',
      mount: 'secret',
      path: 'automation/project',
      field: 'password',
      version: 1,
    });
    preparedPlan = {
      id: 'a'.repeat(32),
      serverId: 'controller',
      projectId: publishedRevision.projectId,
      revisionId: publishedRevision.id,
      revisionDigest: publishedRevision.digest,
      actorId: projectIdentity.user.id,
      digest: 'b'.repeat(64),
      state: 'prepared',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 1800000).toISOString(),
      groupId: 'automation',
      options: body.options,
      targets: [{ serverId: 'dev', host: '127.0.0.1', user: 'fixture', port: 1 }],
      variableNames: [],
      variables: {},
    };
    return route.fulfill({ status: 201, json: preparedPlan });
  });
  await projectsPanel.getByRole('button', { name: 'Save frozen plan for review', exact: true }).click();
  await projectsPanel
    .getByText('Frozen plan saved. A different authorized person must review and approve it.', {
      exact: true,
    })
    .waitFor();
  assert.equal(vaultCalls, 0);
  await ownerPage.route('**/api/servers/controller/ansible/plans/*/content', (route) =>
    route.fulfill({ status: 200, json: preparedPlan }),
  );
  await projectsPanel.getByRole('button', { name: 'Review plan and revision', exact: true }).click();
  await ownerPage.getByText('Reveal plan and playbook?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Reveal review', exact: true }).click();
  await projectsPanel.getByText('Exact frozen review', { exact: true }).waitFor();
  assert.equal(
    await projectsPanel
      .getByRole('button', { name: 'Approve exact plan and revision', exact: true })
      .isDisabled(),
    true,
  );
  await projectsPanel.getByRole('button', { name: 'Hide review', exact: true }).click();
  await ownerPage.unroute('**/api/servers/*/vault**');
  // Submit only the source user's independently approved plan; short-lived
  // Vault tokens exist only in this explicit execution request, never its plan.
  preparedPlan = { ...preparedPlan, state: 'approved', approvedBy: 'fixture-reviewer' };
  let playbookStarts = 0,
    playbookRun;
  await ownerPage.route('**/api/servers/controller/ansible/runs', (route) =>
    route.fulfill({ status: 200, json: playbookRun ? [playbookRun] : [] }),
  );
  await ownerPage.route('**/api/servers/controller/ansible/plans/*/run', (route) => {
    const input = route.request().postDataJSON();
    assert.deepEqual(input.vaultTokens, { dev: 'fixture-vault-run-token' });
    assert.match(input.requestId, /^[a-f0-9]{32}$/);
    playbookStarts++;
    playbookRun = {
      id: input.requestId,
      kind: 'ansible',
      planId: preparedPlan.id,
      serverId: 'controller',
      actorId: projectIdentity.user.id,
      state: 'running',
      createdAt: new Date().toISOString(),
      finishedAt: null,
      artifactsRemoved: false,
    };
    return route.fulfill({ status: 202, json: { run: playbookRun, automaticRetryAllowed: false } });
  });
  await ownerPage.route('**/api/servers/controller/ansible/runs/*/inspect', (route) => {
    playbookRun = { ...playbookRun, state: 'exited', finishedAt: new Date().toISOString() };
    return route.fulfill({
      status: 200,
      json: {
        run: playbookRun,
        observation: { state: 'exited', output: '' },
        result: {
          state: 'playbook_exited',
          version: '2.22.0',
          exitCode: 0,
          hosts: {
            dev: { ok: 1, changed: 0, failures: 0, unreachable: 0, skipped: 0, rescued: 0, ignored: 0 },
          },
          tasks: [{ task: 1, serverId: 'dev', status: 'ok', startedMs: 0, durationMs: 12 }],
          tasksTruncated: false,
        },
        automaticRetryAllowed: false,
      },
    });
  });
  await projectsPanel.getByRole('button', { name: 'Review plan and revision', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Reveal review', exact: true }).click();
  const playbookPanel = ownerPage.getByRole('region', { name: 'Ansible execution', exact: true });
  await playbookPanel
    .getByLabel('Short-lived Vault token for dev', { exact: true })
    .fill('fixture-vault-run-token');
  await playbookPanel.getByRole('button', { name: 'Execute approved plan', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Execute approved playbook?', exact: true })
    .getByRole('button', { name: 'Run approved plan', exact: true })
    .click();
  await playbookPanel.getByText(/running ·/).waitFor();
  assert.equal(
    await playbookPanel.getByLabel('Short-lived Vault token for dev', { exact: true }).inputValue(),
    '',
  );
  await playbookPanel.getByRole('button', { name: 'Inspect run', exact: true }).click();
  await playbookPanel
    .getByRole('region', { name: 'Ansible task history', exact: true })
    .getByText('Task 1', { exact: true })
    .waitFor();
  await playbookPanel.getByRole('cell', { name: '0.012s', exact: true }).waitFor();
  await playbookPanel.getByRole('button', { name: 'Refresh runs', exact: true }).click();
  assert.equal(playbookStarts, 1, 'history refresh replayed a playbook');
  // Preset UI fixture: selected revision/options only, no copied values or approval.
  const presetIdentity = '9'.repeat(32);
  let presetCreates = 0,
    presetPlans = 0;
  await ownerPage.route('**/api/servers/controller/ansible/presets', (route) => {
    if (route.request().method() === 'GET') return route.continue();
    const body = route.request().postDataJSON();
    assert.equal(body.planId, preparedPlan.id);
    assert.equal(body.name, 'Repeat browser checks');
    presetCreates++;
    return route.fulfill({
      status: 201,
      json: {
        id: presetIdentity,
        serverId: 'controller',
        name: body.name,
        createdAt: new Date().toISOString(),
        archived: false,
      },
    });
  });
  await ownerPage.route('**/api/servers/controller/ansible/presets/*/content', (route) =>
    route.fulfill({
      status: 200,
      json: {
        name: 'Repeat browser checks',
        projectId: publishedRevision.projectId,
        revisionId: publishedRevision.id,
        revisionDigest: publishedRevision.digest,
        groupId: 'automation',
        serverIds: ['dev'],
        options: { mode: 'check', tags: [], skipTags: [], verbosity: 0, timeoutSeconds: 300 },
      },
    }),
  );
  await ownerPage.route('**/api/servers/controller/ansible/presets/*/prepare', (route) => {
    const body = route.request().postDataJSON();
    assert.deepEqual(body, { variables: {} });
    presetPlans++;
    return route.fulfill({
      status: 201,
      json: {
        ...preparedPlan,
        id: '8'.repeat(32),
        presetId: presetIdentity,
        state: 'prepared',
        approvedBy: undefined,
        options: { ...preparedPlan.options, vaultPassword: undefined },
      },
    });
  });
  await projectsPanel.getByLabel('New execution preset name', { exact: true }).fill('Repeat browser checks');
  await projectsPanel.getByRole('button', { name: 'Save selection as preset', exact: true }).click();
  await projectsPanel
    .getByText('Selection saved. Variable values, Vault password and approval were not copied.', {
      exact: true,
    })
    .waitFor();
  assert.equal(presetCreates, 1);
  await projectsPanel.getByRole('button', { name: 'Load execution preset', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Load execution preset?', exact: true })
    .getByRole('button', { name: 'Load preset', exact: true })
    .click();
  await projectsPanel
    .getByText('Preset loaded. Enter new values, then save a fresh plan for independent review.', {
      exact: true,
    })
    .waitFor();
  assert.equal(
    await projectsPanel
      .getByRole('checkbox', { name: 'Use Vault for the Ansible Vault password', exact: true })
      .isChecked(),
    false,
  );
  assert.equal(await projectsPanel.getByLabel('Automation group', { exact: true }).isDisabled(), true);
  await projectsPanel.getByRole('button', { name: 'Save frozen plan for review', exact: true }).click();
  await projectsPanel.getByText('Preset ' + presetIdentity, { exact: true }).waitFor();
  assert.equal(presetPlans, 1);
  // Queue and recurring-review UI use mocked admissions; service tests cover execution authority.
  const queuePlan = {
    ...preparedPlan,
    id: '8'.repeat(32),
    presetId: presetIdentity,
    state: 'approved',
    approvedBy: 'fixture-reviewer',
    options: { ...preparedPlan.options, vaultPassword: undefined },
  };
  await ownerPage.route('**/api/servers/controller/ansible/plans/' + queuePlan.id + '/content', (route) =>
    route.fulfill({ status: 200, json: queuePlan }),
  );
  let queuedRows = [],
    reviewSchedules = [],
    queuedCreates = 0,
    scheduledCreates = 0;
  await ownerPage.route('**/api/servers/controller/ansible/queue', (route) =>
    route.fulfill({ status: 200, json: queuedRows }),
  );
  await ownerPage.route('**/api/servers/controller/ansible/plans/*/queue', (route) => {
    const input = route.request().postDataJSON();
    assert.match(input.requestId, /^[a-f0-9]{32}$/);
    queuedCreates++;
    const row = {
      id: input.requestId,
      planId: queuePlan.id,
      serverId: 'controller',
      actorId: projectIdentity.user.id,
      state: 'waiting',
      detail: '',
      notBefore: new Date().toISOString(),
      expiresAt: queuePlan.expiresAt,
      createdAt: new Date().toISOString(),
    };
    queuedRows = [row];
    return route.fulfill({ status: 202, json: row });
  });
  await ownerPage.route('**/api/servers/controller/ansible/queue/*/cancel', (route) => {
    queuedRows = queuedRows.map((q) => ({ ...q, state: 'cancelled', detail: 'cancelled_by_user' }));
    return route.fulfill({ status: 204 });
  });
  await ownerPage.route('**/api/servers/controller/ansible/schedules', (route) => {
    if (route.request().method() === 'GET') return route.fulfill({ status: 200, json: reviewSchedules });
    const input = route.request().postDataJSON();
    assert.equal(input.planId, queuePlan.id);
    assert.equal(input.intervalMinutes, 1440);
    scheduledCreates++;
    const row = {
      id: '7'.repeat(32),
      name: input.name,
      presetId: presetIdentity,
      actorId: projectIdentity.user.id,
      serverId: 'controller',
      intervalMinutes: 1440,
      nextAt: new Date().toISOString(),
      enabled: true,
      lastState: 'scheduled',
      createdAt: new Date().toISOString(),
    };
    reviewSchedules = [row];
    return route.fulfill({ status: 201, json: row });
  });
  await ownerPage.route('**/api/servers/controller/ansible/schedules/*', (route) => {
    const body = route.request().postDataJSON();
    reviewSchedules = reviewSchedules.map((s) => ({
      ...s,
      enabled: body.enabled,
      lastState: body.enabled ? 'scheduled' : 'paused',
    }));
    return route.fulfill({ status: 204 });
  });
  await projectsPanel.getByRole('button', { name: 'Review plan and revision', exact: true }).first().click();
  await ownerPage.getByRole('button', { name: 'Reveal review', exact: true }).click();
  const orchestration = ownerPage.getByRole('region', { name: 'Ansible queue and schedules', exact: true });
  await orchestration.getByRole('button', { name: 'Refresh automation queue', exact: true }).click();
  await orchestration.getByRole('button', { name: 'Queue approved plan', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Queue approved run?', exact: true })
    .getByRole('button', { name: 'Queue run', exact: true })
    .click();
  await orchestration
    .getByText('Queued. Expired or revoked approval blocks admission; an admitted run is never replayed.', {
      exact: true,
    })
    .waitFor();
  assert.equal(queuedCreates, 1);
  await orchestration.getByRole('button', { name: 'Cancel queued run', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Cancel queued run?', exact: true })
    .getByRole('button', { name: 'Cancel queued run', exact: true })
    .click();
  await orchestration.getByLabel('Review schedule name', { exact: true }).fill('Daily browser review');
  await orchestration.getByRole('button', { name: 'Save review schedule', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Schedule fresh plan reviews?', exact: true })
    .getByRole('button', { name: 'Save review schedule', exact: true })
    .click();
  await orchestration
    .getByText(
      'Review schedule saved. Each due plan still needs a different approver and explicit execution.',
      { exact: true },
    )
    .waitFor();
  assert.equal(scheduledCreates, 1);
  await orchestration.getByRole('button', { name: 'Pause review schedule', exact: true }).click();
  await orchestration.getByText('Daily browser review · paused', { exact: true }).waitFor();
  await ownerPage.unroute('**/api/servers/controller/ansible/queue');
  await ownerPage.unroute('**/api/servers/controller/ansible/plans/*/queue');
  await ownerPage.unroute('**/api/servers/controller/ansible/queue/*/cancel');
  await ownerPage.unroute('**/api/servers/controller/ansible/schedules');
  await ownerPage.unroute('**/api/servers/controller/ansible/schedules/*');
  await projectsPanel.getByRole('button', { name: 'Edit selection', exact: true }).click();
  await ownerPage.unroute('**/api/servers/controller/ansible/presets');
  await ownerPage.unroute('**/api/servers/controller/ansible/presets/*/content');
  await ownerPage.unroute('**/api/servers/controller/ansible/presets/*/prepare');
  let sourceImports = 0;
  await ownerPage.route('**/api/servers/controller/ansible/projects/*/revisions/import', (route) => {
    sourceImports++;
    const input = route.request().postDataJSON();
    assert.equal(input.commitSha, 'f'.repeat(40));
    assert.deepEqual(input.paths, ['main.yml']);
    return route.fulfill({
      status: 201,
      json: {
        id: 'f'.repeat(32),
        serverId: 'controller',
        projectId: publishedRevision.projectId,
        digest: 'c'.repeat(64),
        sourceConnectionId: githubConnection,
        sourceRepositoryId: 123,
        sourceCommitSha: input.commitSha,
        createdAt: new Date().toISOString(),
      },
    });
  });
  await helpers.getByText('Import files from GitHub', { exact: true }).click();
  await helpers.getByRole('button', { name: 'Load repository connections', exact: true }).click();
  await helpers.getByLabel('Ansible source repository', { exact: true }).selectOption(githubConnection);
  await helpers.getByLabel('Exact commit SHA', { exact: true }).fill('f'.repeat(40));
  await helpers.getByRole('button', { name: 'Import saved revision', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Import this GitHub revision?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(sourceImports, 0);
  await helpers.getByRole('button', { name: 'Import saved revision', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Import this GitHub revision?', exact: true })
    .getByRole('button', { name: 'Import revision', exact: true })
    .click();
  await projectsPanel.getByText(/Repository 123 · commit/).waitFor();
  assert.equal(sourceImports, 1);
  await ownerPage.unroute('**/api/servers/controller/ansible/projects/*/revisions/import');

  await ownerPage.unroute('**/api/features');
  let environmentStarts = 0,
    environmentRun;
  await ownerPage.route('**/api/features', (route) =>
    route.fulfill({
      status: 200,
      json: {
        automation: true,
        inventory: true,
        jobSupervision: true,
        vault: true,
        operationSupervision: true,
      },
    }),
  );
  await ownerPage.route('**/api/servers/dev/operations/ansible/environment/install', (route) => {
    environmentStarts++;
    const { requestId } = route.request().postDataJSON();
    assert.match(requestId, /^[a-f0-9]{32}$/);
    environmentRun = {
      id: requestId,
      kind: 'operation',
      action: 'ansible-environment-install',
      serverId: 'dev',
      state: 'running',
      finishedAt: null,
    };
    return route.fulfill({ status: 202, json: { run: environmentRun, automaticRetryAllowed: false } });
  });
  await ownerPage.route('**/api/servers/dev/operations/runs/*/inspect', (route) =>
    route.fulfill({
      status: 200,
      json: {
        run: { ...environmentRun, state: 'exited', finishedAt: new Date().toISOString() },
        observation: { state: 'exited', output: '{"state":"ready","version":"2.22.0"}' },
        automaticRetryAllowed: false,
      },
    }),
  );
  await ownerPage.goto(url + '/servers/dev');
  await ownerPage.getByRole('button', { name: 'Ansible', exact: true }).click();
  const environmentPanel = ownerPage.getByRole('region', { name: 'Ansible environment', exact: true });
  await environmentPanel.getByRole('button', { name: 'Install', exact: true }).click();
  await ownerPage.getByText('Install Ansible environment?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Install', exact: true }).last().click();
  await environmentPanel.getByText('Submission state: running', { exact: true }).waitFor();
  assert.equal(
    await environmentPanel.getByRole('button', { name: 'Install', exact: true }).isDisabled(),
    true,
  );
  await environmentPanel.getByRole('button', { name: 'Inspect retained run', exact: true }).click();
  await environmentPanel.getByText('{"state":"ready","version":"2.22.0"}', { exact: true }).waitFor();
  assert.equal(environmentStarts, 1);
  await ownerPage.reload();
  await ownerPage.getByRole('button', { name: 'Ansible', exact: true }).click();
  assert.equal(environmentStarts, 1, 'reload must not resubmit environment work');
  await ownerPage.unroute('**/api/features');
  await ownerPage.unroute('**/api/servers/dev/operations/ansible/environment/install');
  await ownerPage.unroute('**/api/servers/dev/operations/runs/*/inspect');

  // Client-side server navigation must remount the view and discard old identity.
  await ownerPage.evaluate(() =>
    document.querySelector('#app').__vue_app__.config.globalProperties.$router.push('/servers/prod'),
  );
  await ownerPage.getByRole('heading', { name: 'Fixture prod', exact: true }).waitFor();
  assert.equal(await ownerPage.getByRole('button', { name: 'Ansible', exact: true }).count(), 0);
  await ownerPage.evaluate(() =>
    document.querySelector('#app').__vue_app__.config.globalProperties.$router.push('/servers/dev'),
  );
  await ownerPage.getByRole('heading', { name: 'Fixture dev', exact: true }).waitFor();
  // Dedicated Marketplace flow; fake enrollment only, never contacts GitHub.
  let runnerStarts = 0,
    runnerStops = 0,
    runnerCleans = 0,
    runnerItem;
  const runnerToken = 'T'.repeat(26);
  await ownerPage.route('**/api/features', (route) =>
    route.fulfill({
      status: 200,
      json: {
        automation: true,
        inventory: true,
        jobSupervision: true,
        vault: true,
        operationSupervision: true,
      },
    }),
  );
  await ownerPage.route('**/api/servers/dev/github/runners', (route) =>
    route.fulfill({ status: 200, json: runnerItem ? [runnerItem] : [] }),
  );
  await ownerPage.route('**/api/servers/dev/operations/github/runner/start', (route) => {
    runnerStarts++;
    const { registrationToken, requestId, ...profile } = route.request().postDataJSON();
    assert.equal(registrationToken, runnerToken);
    assert.match(requestId, /^[a-f0-9]{32}$/);
    runnerItem = {
      run: {
        id: requestId,
        kind: 'operation',
        action: 'github-runner',
        serverId: 'dev',
        state: 'running',
        finishedAt: null,
        artifactsRemoved: false,
      },
      profile: { ...profile, version: '2.338.2' },
    };
    return route.fulfill({ status: 202, json: { run: runnerItem.run, automaticRetryAllowed: false } });
  });
  await ownerPage.route('**/api/servers/dev/operations/runs/*/cancel', (route) => {
    runnerStops++;
    runnerItem.run.state = 'cancelled';
    runnerItem.run.finishedAt = new Date().toISOString();
    return route.fulfill({
      status: 200,
      json: { run: runnerItem.run, observation: { output: 'runner stopped' }, automaticRetryAllowed: false },
    });
  });
  await ownerPage.route('**/api/servers/dev/operations/runs/*/artifacts', (route) => {
    runnerCleans++;
    runnerItem.run.artifactsRemoved = true;
    return route.fulfill({
      status: 200,
      json: {
        run: runnerItem.run,
        observation: { output: 'artifacts cleaned' },
        automaticRetryAllowed: false,
      },
    });
  });
  await ownerPage.getByRole('button', { name: 'Apps', exact: true }).click();
  await ownerPage.getByText('GitHub Actions Runner', { exact: true }).click();
  const runnerPanel = ownerPage.getByRole('region', { name: 'GitHub runner setup', exact: true });
  await runnerPanel
    .getByLabel('GitHub.com repository or organization URL', { exact: true })
    .fill('https://github.com/example/repository');
  await runnerPanel.getByLabel('Short-lived registration token', { exact: true }).fill(runnerToken);
  await runnerPanel.getByRole('checkbox').check();
  await runnerPanel.getByRole('button', { name: 'Enroll one-job runner', exact: true }).click();
  await ownerPage.getByText('Enroll one-job runner?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Enroll runner', exact: true }).click();
  await runnerPanel.getByText(/nexus-build · running/).waitFor();
  assert.equal(
    await runnerPanel.getByLabel('Short-lived registration token', { exact: true }).inputValue(),
    '',
  );
  await runnerPanel.getByRole('button', { name: 'Stop runner', exact: true }).click();
  await ownerPage.getByText('Stop runner and its job?', { exact: true }).waitFor();
  await ownerPage
    .getByRole('alertdialog', { name: 'Stop runner and its job?', exact: true })
    .getByRole('button', { name: 'Stop runner', exact: true })
    .click();
  await runnerPanel.getByText(/nexus-build · cancelled/).waitFor();
  await runnerPanel.getByRole('button', { name: 'Clean artifacts', exact: true }).click();
  await ownerPage.getByText('Clean runner artifacts?', { exact: true }).waitFor();
  await ownerPage
    .getByRole('alertdialog', { name: 'Clean runner artifacts?', exact: true })
    .getByRole('button', { name: 'Clean artifacts', exact: true })
    .click();
  await runnerPanel.getByText('artifacts cleaned', { exact: true }).waitFor();
  await runnerPanel.getByRole('button', { name: 'Close', exact: true }).click();
  await ownerPage.reload();
  await ownerPage.getByRole('button', { name: 'Apps', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Manage GitHub runners', exact: true }).click();
  await runnerPanel.getByText(/nexus-build · cancelled/).waitFor();
  assert.equal(runnerStarts, 1);
  assert.equal(runnerStops, 1);
  assert.equal(runnerCleans, 1);
  await runnerPanel.getByRole('button', { name: 'Close', exact: true }).click();
  await ownerPage.unroute('**/api/features');
  await ownerPage.unroute('**/api/servers/dev/operations/runs/*/cancel');
  await ownerPage.unroute('**/api/servers/dev/operations/runs/*/artifacts');
  const credentialBudgetStarted = Date.now();
  const invite = await api(owner, '/users/invitations', {
    username: 'viewer',
    roleId: 'viewer',
    scopeType: 'server',
    scopeId: 'dev',
    currentPassword: password,
  });
  assert.equal(invite.status(), 201);
  const invitation = await invite.json();
  await viewerPage.goto(url + '/join#invite=' + invitation.token);
  await viewerPage.getByLabel('New password', { exact: true }).fill(password);
  await viewerPage.getByLabel('Confirm password', { exact: true }).fill(password);
  await viewerPage.getByRole('button', { name: 'Accept invitation', exact: true }).click();
  await viewerPage.getByText('Your account is ready.', { exact: false }).waitFor();
  assert.equal(new URL(viewerPage.url()).hash, '');
  await login(viewerPage, 'viewer');
  let response = await api(viewer, '/servers', undefined, 'GET');
  assert.equal(response.status(), 200);
  const servers = await response.json();
  assert.deepEqual(
    servers.map((s) => s.id),
    ['dev'],
  );
  response = await api(viewer, '/servers/prod/containers/aaaaaaaaaaaa/start', {});
  assert.equal(response.status(), 404);
  response = await api(viewer, '/servers/dev/containers/aaaaaaaaaaaa/start', {});
  assert.equal(response.status(), 403);
  await viewerPage.goto(url + '/servers/dev');
  await viewerPage.getByRole('button', { name: 'Inventory', exact: true }).click();
  await viewerPage.getByRole('heading', { name: 'Observed inventory', exact: true }).waitFor();
  response = await api(viewer, '/servers/dev/inventory/discover', {});
  assert.equal(response.status(), 403);
  response = await api(owner, '/servers/dev/inventory/discover', {});
  assert.equal(response.status(), 200);
  assert.equal((await response.json()).status, 'failed');
  // Public allowlisted observation summaries and per-resource history, UI only.
  const serviceResource = 'd'.repeat(64),
    hostResource = 'f'.repeat(64);
  const serviceDetails = { unit: 'ssh.service', load: 'loaded', active: 'failed', sub: 'failed' };
  await viewerPage.route('**/api/servers/dev/inventory', (route) =>
    route.fulfill({
      status: 200,
      json: {
        items: [
          {
            id: serviceResource,
            kind: 'service',
            displayName: 'ssh.service',
            source: 'systemd',
            dataState: 'fresh',
            lastVerifiedAt: new Date().toISOString(),
            details: serviceDetails,
          },
        ],
        runs: [],
        sources: [],
        changes: [],
        next: '',
      },
    }),
  );
  await viewerPage.route('**/api/servers/dev/inventory?**', (route) =>
    route.fulfill({
      status: 200,
      json: {
        items: [
          {
            id: serviceResource,
            kind: 'service',
            displayName: 'ssh.service',
            source: 'systemd',
            dataState: 'fresh',
            lastVerifiedAt: new Date().toISOString(),
            details: serviceDetails,
          },
        ],
        runs: [],
        sources: [],
        changes: [],
        next: '',
      },
    }),
  );
  await viewerPage.route('**/api/servers/dev/inventory/relationships?**', (route) =>
    route.fulfill({
      status: 200,
      json: {
        items: [
          {
            id: 'c'.repeat(64),
            serverId: 'dev',
            sourceId: hostResource,
            targetId: serviceResource,
            sourceName: 'fixture-host',
            targetName: 'ssh.service',
            kind: 'manages',
            source: 'systemd',
            dataState: 'fresh',
            firstSeenAt: new Date().toISOString(),
            lastVerifiedAt: new Date().toISOString(),
          },
        ],
        next: '',
      },
    }),
  );
  let filteredHistory = 0;
  await viewerPage.route('**/api/servers/dev/inventory/history?**', (route) => {
    const query = new URL(route.request().url()).searchParams;
    if (query.get('resourceId') === serviceResource) filteredHistory++;
    const older = query.get('before') === '9';
    return route.fulfill({
      status: 200,
      json: {
        items: [
          {
            id: older ? 8 : 9,
            serverId: 'dev',
            resourceId: serviceResource,
            runId: 'fixture-scan',
            kind: older ? 'observed' : 'updated',
            at: new Date().toISOString(),
            ...(older
              ? {}
              : {
                  before: {
                    name: 'ssh.service',
                    details: { ...serviceDetails, active: 'active', sub: 'running' },
                  },
                }),
            after: { name: 'ssh.service', details: serviceDetails },
          },
        ],
        next: older ? '' : '9',
      },
    });
  });
  await viewerPage.getByRole('button', { name: 'Refresh records', exact: true }).click();
  await viewerPage.getByRole('cell', { name: 'manages', exact: true }).waitFor();
  await viewerPage.getByRole('button', { name: 'Show history for ssh.service', exact: true }).click();
  const inventoryHistory = viewerPage.getByLabel('Inventory change history', { exact: true });
  await inventoryHistory
    .getByRole('heading', { name: 'Change history · ssh.service', exact: true })
    .waitFor();
  await inventoryHistory.getByText('Compare observed properties', { exact: true }).click();
  await inventoryHistory.getByText('"active": "active"', { exact: false }).waitFor();
  await inventoryHistory.getByRole('button', { name: 'Load older changes', exact: true }).click();
  await inventoryHistory.getByText(/observed · ssh.service/).waitFor();
  assert.equal(filteredHistory, 2);

  await ownerPage.goto(url + '/servers/dev');
  await ownerPage.getByRole('button', { name: 'Inventory', exact: true }).click();
  const collectionControls = ownerPage.getByRole('region', { name: 'Collection settings', exact: true });
  await collectionControls.getByLabel('Interval (minutes)', { exact: true }).fill('10');
  await collectionControls.getByLabel('Freshness (minutes)', { exact: true }).fill('30');
  const policySaved = ownerPage.waitForResponse(
    (response) =>
      response.url().endsWith('/inventory/policy') &&
      response.request().method() === 'PUT' &&
      response.status() === 200,
  );
  await collectionControls.getByRole('button', { name: 'Save collection settings', exact: true }).click();
  await policySaved;
  await collectionControls.getByRole('button', { name: 'Reload settings', exact: true }).click();
  await collectionControls
    .getByRole('button', { name: 'Save collection settings', exact: true })
    .waitFor({ state: 'visible' });
  assert.equal(
    await collectionControls.getByLabel('Freshness (minutes)', { exact: true }).inputValue(),
    '30',
  );
  assert.equal(
    await collectionControls
      .getByLabel('Schedule read-only collection for this host', { exact: true })
      .isChecked(),
    false,
  );
  assert.equal(
    await viewerPage.getByRole('button', { name: 'Save collection settings', exact: true }).count(),
    0,
  );
  const infraDocs = ownerPage.getByRole('region', { name: 'Infrastructure documentation' });
  await infraDocs.getByRole('button', { name: 'Generate report', exact: true }).click();
  await infraDocs.getByLabel('Manual notes').fill('Restart only during the maintenance window.');
  await infraDocs.getByRole('button', { name: 'Save notes', exact: true }).click();
  await infraDocs.getByText('View report text', { exact: true }).click();
  await infraDocs.getByText('Restart only during the maintenance window.', { exact: false }).waitFor();
  const downloadPromise = ownerPage.waitForEvent('download');
  await infraDocs.getByRole('button', { name: 'Download Markdown', exact: true }).click();
  assert.equal((await downloadPromise).suggestedFilename(), 'nexus-inventory.md');
  assert.equal(await viewerPage.getByRole('region', { name: 'Infrastructure documentation' }).count(), 0);

  // UI-only fixture responses verify confirmations without running remote rules.
  const firewall = {
    status: 'active',
    available: true,
    rules: [{ number: 1, to: '22/tcp', action: 'ALLOW', from: 'Anywhere' }],
    ports: [],
  };
  let firewallMutations = 0;
  for (const page of [ownerPage, viewerPage]) {
    await page.route('**/api/servers/dev/firewall', (route) =>
      route.fulfill({ status: 200, json: firewall }),
    );
    await page.route('**/api/servers/dev/firewall/**', (route) => {
      firewallMutations++;
      return route.fulfill({ status: 200, json: { ok: true } });
    });
  }
  await viewerPage.getByRole('button', { name: 'Firewall', exact: true }).click();
  await viewerPage.getByText('UFW Firewall', { exact: true }).waitFor();
  assert.equal(await viewerPage.getByRole('button', { name: 'Disable', exact: true }).count(), 0);
  assert.equal(await viewerPage.getByRole('button', { name: 'Add Rule', exact: true }).count(), 0);
  await ownerPage.goto(url + '/servers/dev');
  await ownerPage.getByRole('button', { name: 'Firewall', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Disable', exact: true }).click();
  await ownerPage.getByText('Disable firewall?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(firewallMutations, 0);
  await ownerPage.getByRole('button', { name: 'Delete firewall rule 1', exact: true }).click();
  await ownerPage.getByText('Delete firewall rule?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(firewallMutations, 0);

  // Local UI fixtures exercise interruption confirmations and failed 200 responses.
  let disruptiveMutations = 0;
  await ownerPage.route('**/api/servers/dev/containers', (route) =>
    route.fulfill({
      status: 200,
      json: [
        {
          id: 'aaaaaaaaaaaa',
          name: 'fixture-container',
          image: 'fixture:local',
          state: 'running',
          status: 'running',
          ports: '',
        },
      ],
    }),
  );
  await ownerPage.route('**/api/servers/dev/containers/*/*', (route) => {
    disruptiveMutations++;
    return route.fulfill({ status: 200, json: { ok: true } });
  });
  let yamlWrites = 0,
    composeFixtureContent = 'services: {}';
  await ownerPage.route('**/api/servers/dev/compose**', (route) => {
    if (route.request().method() === 'GET')
      return route.fulfill({
        status: 200,
        json: { content: composeFixtureContent, path: '/root/docker-compose.yml' },
      });
    if (route.request().method() === 'PUT') {
      yamlWrites++;
      composeFixtureContent = route.request().postDataJSON().content;
      return route.fulfill({ status: 200, json: { ok: true } });
    }
    disruptiveMutations++;
    return route.fulfill({
      status: 200,
      headers: { 'X-Operation-ID': 'c'.repeat(32) },
      json: { ok: false, error: 'Fixture command failed', output: '' },
    });
  });
  await ownerPage.getByRole('button', { name: 'Containers', exact: true }).click();
  await ownerPage.getByText('fixture-container', { exact: true }).waitFor();
  await ownerPage.getByText('fixture-container', { exact: true }).click();
  for (const action of ['Stop', 'Restart', 'Remove']) {
    await ownerPage.getByRole('button', { name: action, exact: true }).click();
    await ownerPage.getByText(action + ' container', { exact: true }).waitFor();
    await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  }
  assert.equal(disruptiveMutations, 0);
  await ownerPage.getByRole('button', { name: 'YAML Editor', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Open', exact: true }).click();
  const yamlEditor = ownerPage.getByRole('region', { name: 'YAML file editor', exact: true });
  await yamlEditor
    .getByRole('textbox', { name: 'YAML file content', exact: true })
    .fill('services:\n  web:\n    image: nginx:stable\n');
  assert.equal(
    await yamlEditor.getByRole('button', { name: 'up -d', exact: true }).isDisabled(),
    true,
    'unsaved edits cannot be deployed',
  );
  await yamlEditor.getByRole('button', { name: 'Save YAML', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Replace YAML file?', exact: true })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  assert.equal(yamlWrites, 0);
  await yamlEditor.getByRole('button', { name: 'Save YAML', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Replace YAML file?', exact: true })
    .getByRole('button', { name: 'Save YAML', exact: true })
    .click();
  await yamlEditor.getByText('YAML file saved.', { exact: true }).waitFor();
  assert.equal(yamlWrites, 1);
  assert.equal(disruptiveMutations, 0, 'saving YAML cannot deploy it');
  for (const [button, title] of [
    ['up -d', 'Apply Compose deployment?'],
    ['down', 'Stop Compose deployment?'],
  ]) {
    await ownerPage.getByRole('button', { name: button, exact: true }).click();
    await ownerPage.getByText(title, { exact: true }).waitFor();
    await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  }
  assert.equal(disruptiveMutations, 0);
  await ownerPage.getByRole('button', { name: 'down', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Stop deployment', exact: true }).click();
  await ownerPage
    .getByText(/Fixture command failed/)
    .first()
    .waitFor();
  assert.equal(disruptiveMutations, 1);
  assert.equal(await ownerPage.getByText('docker compose down — done', { exact: true }).count(), 0);
  // General Kubernetes YAML uses file permissions, not Compose execution.
  let genericYamlWrites = 0,
    genericYamlContent =
      'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n';
  await ownerPage.route('**/api/servers/dev/files/preview**', (route) =>
    route.fulfill({ status: 200, json: { content: genericYamlContent, truncated: false, binary: false } }),
  );
  await ownerPage.route('**/api/servers/dev/files', (route) => {
    assert.equal(route.request().method(), 'PUT');
    genericYamlWrites++;
    genericYamlContent = route.request().postDataJSON().content;
    return route.fulfill({ status: 200, json: { ok: true } });
  });
  await yamlEditor.getByLabel('Server YAML path', { exact: true }).fill('/opt/deployment.yaml');
  await yamlEditor.getByRole('button', { name: 'Open', exact: true }).click();
  await yamlEditor.getByText(/Editing \/opt\/deployment.yaml/).waitFor();
  assert.equal(
    await yamlEditor.getByRole('button', { name: 'up -d', exact: true }).count(),
    0,
    'Kubernetes editor must not offer Compose execution',
  );
  await yamlEditor
    .getByRole('textbox', { name: 'YAML file content', exact: true })
    .fill('apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  ');
  await yamlEditor.getByRole('button', { name: 'Suggest keys', exact: true }).click();
  await ownerPage.getByRole('listbox').waitFor();
  await ownerPage.getByRole('option').filter({ hasText: 'replicas' }).first().click();
  await yamlEditor
    .getByRole('textbox', { name: 'YAML file content', exact: true })
    .fill('apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 2\n');
  await yamlEditor.getByRole('button', { name: 'Save YAML', exact: true }).click();
  await ownerPage
    .getByRole('alertdialog', { name: 'Replace YAML file?', exact: true })
    .getByRole('button', { name: 'Save YAML', exact: true })
    .click();
  await yamlEditor.getByText('YAML file saved.', { exact: true }).waitFor();
  assert.equal(genericYamlWrites, 1);
  await ownerPage.unroute('**/api/servers/dev/files/preview**');
  await ownerPage.unroute('**/api/servers/dev/files');
  await ownerPage.goto(url + '/settings');
  await ownerPage.getByRole('checkbox', { name: 'Show YAML Editor', exact: true }).uncheck();
  await ownerPage.getByRole('checkbox', { name: 'Show Terminal', exact: true }).uncheck();
  await ownerPage.getByRole('checkbox', { name: 'Show GitHub runners', exact: true }).uncheck();
  await ownerPage.reload();
  assert.equal(
    await ownerPage.getByRole('checkbox', { name: 'Show YAML Editor', exact: true }).isChecked(),
    false,
  );
  let hiddenTerminalSockets = 0;
  const trackHiddenSocket = () => {
    hiddenTerminalSockets++;
  };
  ownerPage.on('websocket', trackHiddenSocket);
  await ownerPage.goto(url + '/servers/dev');
  await ownerPage.getByRole('heading', { name: 'Fixture dev', exact: true }).waitFor();
  assert.equal(await ownerPage.getByRole('button', { name: 'YAML Editor', exact: true }).count(), 0);
  assert.equal(await ownerPage.getByRole('button', { name: 'Terminal', exact: true }).count(), 0);
  assert.equal(hiddenTerminalSockets, 0);
  ownerPage.off('websocket', trackHiddenSocket);
  await ownerPage.goto(url + '/automation');
  await ownerPage.getByLabel('GitHub permission scope', { exact: true }).selectOption('controller');
  assert.equal(
    await ownerPage.getByRole('region', { name: 'GitHub organization runners', exact: true }).count(),
    0,
    'hidden runner tool still showed organization controls',
  );
  await ownerPage.goto(url + '/settings');
  await ownerPage.getByRole('checkbox', { name: 'Show GitHub runners', exact: true }).check();
  await ownerPage.getByRole('checkbox', { name: 'Show YAML Editor', exact: true }).check();
  await ownerPage.getByRole('checkbox', { name: 'Show Terminal', exact: true }).check();
  await ownerPage.goto(url + '/servers/dev');
  await ownerPage.getByRole('button', { name: 'YAML Editor', exact: true }).waitFor();
  // Renewal stays available after HTTPS is enabled; cancellation sends no request.
  const certificateRule = {
    id: 'fixture-certificate',
    serverId: 'dev',
    domain: 'certificate.nexus.test',
    target: '127.0.0.1:9999',
    proxyType: 'nginx',
    sslEnabled: true,
  };
  const cleanupWarning = 'Certificate installed, but the DNS plugin reported a cleanup failure.';
  let renewalRequests = 0,
    renewalBody;
  await ownerPage.route('**/api/servers/dev/proxy', (route) =>
    route.fulfill({ status: 200, json: [certificateRule] }),
  );
  await ownerPage.route('**/api/servers/dev/proxy/detect', (route) =>
    route.fulfill({ status: 200, json: { proxyType: 'nginx', version: 'fixture' } }),
  );
  await ownerPage.route('**/api/servers/dev/proxy/fixture-certificate/ssl', (route) => {
    renewalRequests++;
    renewalBody = route.request().postDataJSON();
    return route.fulfill({
      status: 200,
      json: {
        rule: certificateRule,
        output: 'Fixture certificate renewed',
        warning: cleanupWarning,
        dnsCleanupStatus: 'reported_failure',
      },
    });
  });
  await ownerPage.getByRole('button', { name: 'Proxy', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Renew', exact: true }).click();
  await ownerPage.getByRole('checkbox').check();
  await ownerPage
    .getByPlaceholder('Token with DNS:Edit permission', { exact: true })
    .fill('browser disposable token');
  await ownerPage.getByRole('button', { name: 'Renew certificate', exact: true }).click();
  await ownerPage.getByText('Renew certificate?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).last().click();
  assert.equal(renewalRequests, 0);
  await ownerPage.getByRole('button', { name: 'Renew certificate', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Renew', exact: true }).last().click();
  await ownerPage.getByRole('alert').filter({ hasText: cleanupWarning }).waitFor();
  assert.equal(renewalRequests, 1);
  assert.equal(renewalBody.renew, true);
  assert.equal(renewalBody.wildcard, true);
  assert.equal(renewalBody.cfToken, 'browser disposable token');
  await ownerPage.getByRole('button', { name: 'Close', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Renew', exact: true }).click();
  await ownerPage.getByRole('checkbox').check();
  assert.equal(
    await ownerPage.getByPlaceholder('Token with DNS:Edit permission', { exact: true }).inputValue(),
    '',
  );
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  // Supervision controls inspect/cancel a known run; they never enqueue a retry.
  const supervisedTask = {
    id: 'fixture-task',
    serverId: 'dev',
    actorId: 'owner',
    createdBy: 'owner',
    name: 'Supervised fixture',
    command: 'fixture only',
    intervalMinutes: 60,
    enabled: true,
    supervised: true,
    lastStatus: 'running',
    lastOutput: '',
    createdAt: new Date().toISOString(),
  };
  const supervisedRun = {
    id: 'e'.repeat(32),
    taskId: supervisedTask.id,
    serverId: 'dev',
    actorId: 'owner',
    state: 'unknown',
    exitCode: null,
    truncated: false,
    artifactsRemoved: false,
    detail: '',
    createdAt: new Date().toISOString(),
    dispatchStartedAt: new Date().toISOString(),
    cancelRequestedAt: null,
    verifiedAt: null,
    finishedAt: null,
  };
  let runInspections = 0,
    runCancellations = 0,
    runReplays = 0;
  const runURL = '**/api/servers/dev/tasks/fixture-task/runs/' + supervisedRun.id;
  await ownerPage.route('**/api/servers/dev/tasks', (route) =>
    route.fulfill({ status: 200, json: [supervisedTask] }),
  );
  await ownerPage.route('**/api/servers/dev/tasks/fixture-task/runs', (route) =>
    route.fulfill({ status: 200, json: [supervisedRun] }),
  );
  await ownerPage.route('**/api/servers/dev/tasks/fixture-task/run', (route) => {
    runReplays++;
    return route.fulfill({ status: 409, json: { error: 'Unresolved run' } });
  });
  await ownerPage.route(runURL + '/inspect', (route) => {
    runInspections++;
    return route.fulfill({
      status: 200,
      json: {
        run: supervisedRun,
        observation: { state: 'unknown', verified: false, empty: false, output: '', noDispatch: false },
        automaticRetryAllowed: false,
      },
    });
  });
  await ownerPage.route(runURL + '/cancel', (route) => {
    runCancellations++;
    supervisedRun.state = 'cancelled';
    supervisedRun.verifiedAt = new Date().toISOString();
    supervisedRun.finishedAt = new Date().toISOString();
    supervisedTask.enabled = false;
    supervisedTask.lastStatus = 'cancelled';
    return route.fulfill({
      status: 200,
      json: {
        run: supervisedRun,
        observation: { state: 'cancelled', verified: true, empty: true, output: '', noDispatch: false },
        automaticRetryAllowed: false,
      },
    });
  });
  await ownerPage.getByRole('button', { name: 'Tasks', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Run history for Supervised fixture', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Inspect remote state', exact: true }).click();
  await ownerPage
    .getByText('State is unverified. Inspect the target before retrying. Automatic retry is disabled.', {
      exact: true,
    })
    .waitFor();
  assert.equal(runInspections, 1);
  assert.equal(runReplays, 0);
  await ownerPage.getByRole('button', { name: 'Cancel run', exact: true }).click();
  await ownerPage.getByText('Cancel supervised run?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(runCancellations, 0);
  await ownerPage.getByText('Cancel supervised run?', { exact: true }).waitFor({ state: 'hidden' });
  await ownerPage
    .getByRole('region', { name: 'Supervised run history' })
    .getByRole('button', { name: 'Cancel run', exact: true })
    .click();
  await ownerPage.getByRole('button', { name: 'Cancel run', exact: true }).last().click();
  await ownerPage.getByRole('status').filter({ hasText: 'Observed: cancelled' }).waitFor();
  assert.equal(runCancellations, 1);
  assert.equal(runReplays, 0);
  await ownerPage.getByText('Paused', { exact: true }).waitFor();
  // Vault saves public settings; tokens are one-request inputs and never retained.
  await ownerPage.getByRole('button', { name: 'Vault', exact: true }).click();
  await ownerPage.getByRole('heading', { name: 'HashiCorp Vault', exact: true }).waitFor();
  await ownerPage.getByLabel('TLS certificate DNS name', { exact: true }).fill('vault.fixture');
  await ownerPage.getByRole('button', { name: 'Save connection', exact: true }).click();
  await ownerPage.getByText('Vault connection saved', { exact: true }).waitFor();
  let vaultInspections = 0,
    vaultDeletes = 0;
  await ownerPage.route('**/api/servers/dev/vault/inspect', (route) => {
    vaultInspections++;
    const body = route.request().postDataJSON();
    assert.equal(body.token, vaultInspections === 1 ? 'browser-vault-fixture' : 'browser-second-fixture');
    if (vaultInspections === 2)
      return route.fulfill({
        status: 502,
        json: { error: 'Fixture Vault unavailable', code: 'vault_unavailable' },
      });
    return route.fulfill({
      status: 200,
      json: {
        health: { initialized: true, sealed: false, standby: false, status: 200 },
        mountsStatus: 'ok',
        mounts: [{ path: 'secret/', type: 'kv', version: '2', description: 'Fixture engine' }],
      },
    });
  });
  await ownerPage
    .getByLabel('Short-lived Vault token (optional for health)', { exact: true })
    .fill('browser-vault-fixture');
  await ownerPage.getByRole('button', { name: 'Inspect Vault', exact: true }).click();
  await ownerPage.getByRole('cell', { name: 'secret/', exact: true }).waitFor();
  assert.equal(
    await ownerPage.getByLabel('Short-lived Vault token (optional for health)', { exact: true }).inputValue(),
    '',
  );
  // Access-only controls use typed requests and clear credentials after each call.
  let accessCalls = 0;
  await ownerPage.route('**/api/servers/dev/vault/access/**', (route) => {
    accessCalls++;
    const body = route.request().postDataJSON();
    assert.equal(body.token, 'browser-access-fixture');
    const action = route.request().url().split('/').at(-1);
    if (action === 'auth')
      return route.fulfill({
        status: 200,
        json: {
          methods: [{ path: 'token/', type: 'token', description: 'Token authentication', defaultTTL: 0 }],
        },
      });
    if (action === 'policies') return route.fulfill({ status: 200, json: { policies: ['example'] } });
    if (action === 'policy') {
      assert.equal(body.name, 'example');
      return route.fulfill({
        status: 200,
        json: { name: 'example', policy: 'path "secret/*" { capabilities = ["read"] }' },
      });
    }
    assert.deepEqual(body.paths, ['secret/data/demo', 'sys/auth']);
    return route.fulfill({
      status: 200,
      json: { capabilities: { 'secret/data/demo': ['read'], 'sys/auth': ['deny'] } },
    });
  });
  const accessToken = ownerPage.getByLabel('Vault token for access inspection', { exact: true });
  await accessToken.fill('browser-access-fixture');
  await ownerPage.getByRole('button', { name: 'Inspect auth methods', exact: true }).click();
  await ownerPage.getByRole('cell', { name: 'token/', exact: true }).waitFor();
  assert.equal(await accessToken.inputValue(), '');
  await accessToken.fill('browser-access-fixture');
  await ownerPage.getByRole('button', { name: 'List ACL policies', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'example', exact: true }).click();
  await accessToken.fill('browser-access-fixture');
  await ownerPage.getByRole('button', { name: 'Read ACL policy', exact: true }).click();
  await ownerPage.getByText('path "secret/*" { capabilities = ["read"] }', { exact: true }).waitFor();
  await ownerPage
    .getByLabel('Capability paths (one per line)', { exact: true })
    .fill('secret/data/demo\nsys/auth');
  await accessToken.fill('browser-access-fixture');
  await ownerPage.getByRole('button', { name: 'Inspect caller capabilities', exact: true }).click();
  await ownerPage.getByRole('cell', { name: 'deny', exact: true }).waitFor();
  assert.equal(await accessToken.inputValue(), '');
  assert.equal(accessCalls, 4);
  // Guided administration uses the real permission-filtered operation catalog.
  const adminPanel = ownerPage.getByRole('region', { name: 'Vault administration', exact: true });
  const actionMenu = adminPanel.getByLabel('Management action', { exact: true });
  response = await api(owner, '/servers/dev/vault/admin/operations', undefined, 'GET');
  assert.equal(response.status(), 200);
  assert.ok((await response.json()).operations.some((op) => op.id === 'policy-read'));
  assert.equal(
    await ownerPage.locator('section[aria-label="Vault administration"]').count(),
    1,
    'Vault administration component must render',
  );
  await actionMenu.selectOption('policy-read');
  assert.equal(await actionMenu.locator('option[value="token-create"]').count(), 0);
  let adminCalls = 0;
  await ownerPage.route('**/api/servers/dev/vault/admin/policy-*', (route) => {
    adminCalls++;
    const body = route.request().postDataJSON();
    assert.equal(body.token, 'browser-admin-fixture');
    assert.equal(body.params.name, 'browser-policy');
    const action = route.request().url().split('/').at(-1);
    if (action === 'policy-read')
      return route.fulfill({
        status: 200,
        json: {
          dataJson: JSON.stringify({
            name: 'browser-policy',
            exists: true,
            policy: 'path "secret/data/browser" { capabilities = ["read"] }',
          }),
          revision: 'a'.repeat(64),
          automaticRetryAllowed: false,
        },
      });
    assert.equal(action, 'policy-save');
    assert.equal(body.confirmation, 'policy-save');
    assert.equal(body.params.revision, 'a'.repeat(64));
    assert.ok(body.params.policy.includes('secret/data/browser'));
    return route.fulfill({
      status: 502,
      json: { error: 'Fixture admin write outcome unknown; inspect before retrying', code: 'remote_unknown' },
    });
  });
  await adminPanel.getByLabel('Name *', { exact: true }).fill('browser-policy');
  await adminPanel.getByLabel('Vault token for this action', { exact: true }).fill('browser-admin-fixture');
  await adminPanel.getByRole('button', { name: 'Read policy and revision', exact: true }).click();
  await adminPanel.getByText('Policy revision: ' + 'a'.repeat(64), { exact: true }).waitFor();
  assert.equal(await adminPanel.getByLabel('Vault token for this action', { exact: true }).inputValue(), '');
  await adminPanel.getByRole('button', { name: 'Edit this policy', exact: true }).click();
  assert.equal(await actionMenu.inputValue(), 'policy-save');
  assert.equal(await adminPanel.getByLabel('Name *', { exact: true }).inputValue(), 'browser-policy');
  const adminSave = adminPanel.getByRole('button', { name: 'Save ACL policy', exact: true });
  assert.equal(await adminSave.isDisabled(), true);
  await adminPanel.getByLabel('Vault token for this action', { exact: true }).fill('browser-admin-fixture');
  await adminPanel
    .getByLabel('To confirm these changes, type policy-save', { exact: true })
    .fill('policy-save');
  await adminSave.click();
  await adminPanel.getByRole('alert').filter({ hasText: 'Fixture admin write outcome unknown' }).waitFor();
  await ownerPage.waitForTimeout(100);
  assert.equal(adminCalls, 2);
  assert.equal(await adminPanel.getByLabel('Vault token for this action', { exact: true }).inputValue(), '');
  assert.equal(
    await adminPanel.getByLabel('To confirm these changes, type policy-save', { exact: true }).inputValue(),
    '',
  );
  await actionMenu.selectOption('userpass-save');
  await adminPanel
    .getByLabel('New password (leave empty to keep on an existing user)', { exact: true })
    .fill('browser-transient-password');
  await actionMenu.selectOption('token-self');
  assert.equal(
    await adminPanel
      .getByLabel('New password (leave empty to keep on an existing user)', { exact: true })
      .count(),
    0,
  );
  assert.equal(
    await ownerPage.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }).includes('browser-transient-password'),
    ),
    false,
  );
  // KV controls keep reveal separate, require CAS and never retry uncertain writes.
  assert.equal(await ownerPage.getByRole('button', { name: 'Reveal values', exact: true }).count(), 0);
  let kvMetadata = 0,
    kvWrites = 0,
    precisionWrites = 0;
  await ownerPage.route('**/api/servers/dev/vault/kv/**', (route) => {
    const body = route.request().postDataJSON();
    assert.equal(body.token, 'browser-kv-fixture');
    assert.equal(body.mount, 'secret');
    assert.equal(body.path, 'demo');
    if (route.request().url().endsWith('/read'))
      return route.fulfill({
        status: 200,
        json: {
          dataJson: '{"large":9007199254740993,"decimal":0.1000000000000000001}',
          metadata: { version: 5 },
          automaticRetryAllowed: false,
        },
      });
    if (route.request().url().endsWith('/metadata')) {
      kvMetadata++;
      return route.fulfill({
        status: 200,
        json: { metadata: { version: kvMetadata === 1 ? 3 : 4 }, automaticRetryAllowed: false },
      });
    }
    if (body.dataJson.includes('rawNumber')) {
      precisionWrites++;
      assert.ok(body.dataJson.includes('0.1000000000000000001'));
      return route.fulfill({
        status: 400,
        json: { error: 'Fixture precision rejected: use strings', code: 'bad_request' },
      });
    }
    kvWrites++;
    assert.equal(body.version, kvWrites === 1 ? 3 : 4);
    assert.deepEqual(JSON.parse(body.dataJson), { value: 'browser-private-kv-value' });
    if (kvWrites === 1)
      return route.fulfill({
        status: 409,
        json: { error: 'Fixture version conflict', code: 'vault_conflict' },
      });
    if (kvWrites === 2)
      return route.fulfill({
        status: 502,
        json: { error: 'Fixture uncertain write: inspect remote state', code: 'remote_unknown' },
      });
    return route.fulfill({ status: 200, json: { metadata: { version: 5 }, automaticRetryAllowed: false } });
  });
  await ownerPage.getByLabel('Secret key or directory', { exact: true }).fill('demo');
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Read version metadata', exact: true }).click();
  await ownerPage.getByLabel('Expected current version', { exact: true }).waitFor();
  await ownerPage.waitForFunction(
    () =>
      document.querySelector('section[aria-label="Vault KV-v2 secrets"] input[type="number"]')?.value === '3',
  );
  assert.equal(
    await ownerPage.getByLabel('Vault token for this operation', { exact: true }).inputValue(),
    '',
  );
  await ownerPage
    .getByLabel('New secret JSON', { exact: true })
    .fill('{"value":"browser-private-kv-value","rawNumber":0.1000000000000000001}');
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Write secret version', exact: true }).click();
  await ownerPage.getByText('Write Vault secret version?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  await ownerPage.getByText('Write Vault secret version?', { exact: true }).waitFor({ state: 'hidden' });
  assert.equal(kvWrites, 0);
  await ownerPage.getByRole('button', { name: 'Write secret version', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Write version', exact: true }).click();
  await ownerPage.getByRole('alert').filter({ hasText: 'Fixture precision rejected' }).waitFor();
  assert.equal(precisionWrites, 1);
  assert.equal(kvWrites, 0);
  await ownerPage.getByLabel('New secret JSON', { exact: true }).fill('{"value":"browser-private-kv-value"}');
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Write secret version', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Write version', exact: true }).click();
  await ownerPage.getByRole('alert').filter({ hasText: 'Fixture version conflict' }).waitFor();
  assert.equal(kvWrites, 1);
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Read version metadata', exact: true }).click();
  await ownerPage.waitForFunction(
    () =>
      document.querySelector('section[aria-label="Vault KV-v2 secrets"] input[type="number"]')?.value === '4',
  );
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Write secret version', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Write version', exact: true }).click();
  await ownerPage.getByRole('alert').filter({ hasText: 'Fixture uncertain write' }).waitFor();
  assert.equal(kvWrites, 2);
  assert.equal(
    await ownerPage.getByLabel('Vault token for this operation', { exact: true }).inputValue(),
    '',
  );
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Write secret version', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Write version', exact: true }).click();
  await ownerPage.getByRole('status').filter({ hasText: 'Written version 5.' }).waitFor();
  assert.equal(kvWrites, 3);
  assert.equal(kvMetadata, 2);
  assert.equal(await ownerPage.getByLabel('New secret JSON', { exact: true }).inputValue(), '{}');
  // Grant reveal explicitly and verify the browser displays JSON text unchanged.
  response = await api(owner, '/auth/me', undefined, 'GET');
  const ownerIdentity = await response.json();
  response = await api(owner, '/grants', {
    principalId: ownerIdentity.user.id,
    roleId: 'secret-reader',
    scopeType: 'server',
    scopeId: 'dev',
    currentPassword: password,
  });
  assert.equal(response.status(), 201);
  vaultInspections = 0;
  response = await api(owner, '/auth/me', undefined, 'GET');
  assert.equal(response.status(), 401);
  await login(ownerPage, 'owner');
  await ownerPage.goto(url + '/servers/dev');
  await ownerPage.getByRole('button', { name: 'Vault', exact: true }).click();
  await ownerPage
    .getByLabel('Short-lived Vault token (optional for health)', { exact: true })
    .fill('browser-vault-fixture');
  await ownerPage.getByRole('button', { name: 'Inspect Vault', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Reveal values', exact: true }).waitFor();
  await ownerPage.getByLabel('Secret key or directory', { exact: true }).fill('demo');
  await ownerPage.getByLabel('Vault token for this operation', { exact: true }).fill('browser-kv-fixture');
  await ownerPage.getByRole('button', { name: 'Reveal values', exact: true }).click();
  await ownerPage
    .getByText('{"large":9007199254740993,"decimal":0.1000000000000000001}', { exact: true })
    .waitFor();
  await ownerPage.getByRole('button', { name: 'Hide values', exact: true }).click();
  // A separate reveal grant unlocks one-time credential actions after re-login.
  const sensitiveAdmin = ownerPage.getByRole('region', { name: 'Vault administration', exact: true });
  await sensitiveAdmin.getByLabel('Management action', { exact: true }).selectOption('token-create');
  let issuedTokens = 0;
  await ownerPage.route('**/api/servers/dev/vault/admin/token-create', (route) => {
    issuedTokens++;
    const body = route.request().postDataJSON();
    assert.equal(body.token, 'browser-admin-issuer');
    assert.deepEqual(body.params.policies, ['default']);
    assert.equal(body.params.ttl, 600);
    return route.fulfill({
      status: 200,
      json: {
        dataJson: '{"client_token":"browser-one-time-child","accessor":"fixture-accessor"}',
        automaticRetryAllowed: false,
      },
    });
  });
  await sensitiveAdmin.getByLabel('Policies (one per line, never root) *', { exact: true }).fill('default');
  await sensitiveAdmin.getByLabel('TTL in seconds (maximum 86400) *', { exact: true }).fill('600');
  await sensitiveAdmin.getByLabel('Display name *', { exact: true }).fill('browser-child');
  await sensitiveAdmin
    .getByLabel('Vault token for this action', { exact: true })
    .fill('browser-admin-issuer');
  await sensitiveAdmin
    .getByLabel('To confirm these changes, type token-create', { exact: true })
    .fill('token-create');
  assert.equal(
    await sensitiveAdmin
      .getByRole('button', { name: 'Create bounded child token', exact: true })
      .isDisabled(),
    true,
  );
  await sensitiveAdmin
    .getByLabel('I intend to reveal this action’s sensitive result.', { exact: false })
    .check();
  await sensitiveAdmin.getByRole('button', { name: 'Create bounded child token', exact: true }).click();
  await sensitiveAdmin.getByRole('button', { name: 'Reveal one-time result', exact: true }).waitFor();
  assert.equal(await sensitiveAdmin.locator('pre').count(), 0);
  await sensitiveAdmin.getByRole('button', { name: 'Reveal one-time result', exact: true }).click();
  await sensitiveAdmin
    .getByText('{"client_token":"browser-one-time-child","accessor":"fixture-accessor"}', { exact: true })
    .waitFor();
  await sensitiveAdmin.getByRole('button', { name: 'Hide and clear result', exact: true }).click();
  assert.equal(await sensitiveAdmin.locator('pre').count(), 0);
  assert.equal(issuedTokens, 1);
  assert.equal(
    await ownerPage.getByLabel('Vault token for this operation', { exact: true }).inputValue(),
    '',
  );
  await ownerPage
    .getByLabel('Short-lived Vault token (optional for health)', { exact: true })
    .fill('browser-second-fixture');
  await ownerPage.getByRole('button', { name: 'Inspect Vault', exact: true }).click();
  await ownerPage.getByRole('alert').filter({ hasText: 'Fixture Vault unavailable' }).waitFor();
  assert.equal(
    await ownerPage.getByLabel('Short-lived Vault token (optional for health)', { exact: true }).inputValue(),
    '',
  );
  assert.equal(
    await ownerPage.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }).includes('browser-vault-fixture'),
    ),
    false,
  );
  await ownerPage.route('**/api/servers/dev/vault', (route) => {
    if (route.request().method() === 'DELETE') {
      vaultDeletes++;
      return route.fulfill({ status: 204 });
    }
    return route.continue();
  });
  await ownerPage.getByRole('button', { name: 'Remove connection', exact: true }).click();
  await ownerPage.getByText('Remove Vault connection?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(vaultDeletes, 0);
  assert.equal(vaultInspections, 2);
  assert.equal(await viewerPage.getByRole('button', { name: 'Vault', exact: true }).count(), 0);
  response = await api(viewer, '/servers/dev/vault', undefined, 'GET');
  assert.equal(response.status(), 403);
  // Interactive supervision retains the client-chosen ID across uncertain replies.
  let interactiveStarts = 0,
    interactiveInspections = 0,
    interactiveCancels = 0,
    interactiveRun;
  await ownerPage.route('**/api/features', (route) =>
    route.fulfill({
      status: 200,
      json: { inventory: true, jobSupervision: true, vault: true, operationSupervision: true },
    }),
  );
  await ownerPage.route('**/api/servers/dev/operations/**', (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    const snapshot = (output = '') => ({
      run: interactiveRun,
      observation: {
        state: interactiveRun.state,
        verified: interactiveRun.state !== 'unknown',
        empty: !!interactiveRun.finishedAt,
        exitCode: null,
        output,
        truncated: false,
        released: interactiveRun.artifactsRemoved,
        detail: '',
        noDispatch: false,
      },
      automaticRetryAllowed: false,
    });
    if (path.endsWith('/compose/up')) {
      interactiveStarts++;
      const body = request.postDataJSON();
      assert.match(body.requestId, /^[a-f0-9]{32}$/);
      assert.equal(body.path, '/root/docker-compose.yml');
      interactiveRun = {
        id: body.requestId,
        kind: 'operation',
        action: 'compose-up',
        taskId: '',
        serverId: 'dev',
        actorId: 'fixture',
        targetId: 'b'.repeat(64),
        state: 'unknown',
        exitCode: null,
        truncated: false,
        artifactsRemoved: false,
        detail: '',
        createdAt: new Date().toISOString(),
        dispatchStartedAt: new Date().toISOString(),
        cancelRequestedAt: null,
        verifiedAt: null,
        finishedAt: null,
      };
      return route.fulfill({
        status: 502,
        json: {
          error: 'Fixture submission unconfirmed; inspect retained run',
          code: 'remote_unknown',
          run: interactiveRun,
        },
      });
    }
    if (path.endsWith('/runs'))
      return route.fulfill({ status: 200, json: interactiveRun ? [interactiveRun] : [] });
    if (path.endsWith('/inspect')) {
      interactiveInspections++;
      interactiveRun.state = 'running';
      return route.fulfill({ status: 200, json: snapshot() });
    }
    if (path.endsWith('/cancel')) {
      interactiveCancels++;
      interactiveRun.state = 'cancelled';
      interactiveRun.finishedAt = new Date().toISOString();
      return route.fulfill({ status: 200, json: snapshot() });
    }
    return route.fulfill({ status: 200, json: snapshot('browser-interactive-private-output') });
  });
  const interactiveFeatures = ownerPage.waitForResponse('**/api/features');
  await ownerPage.goto(url + '/servers/dev');
  await interactiveFeatures;
  await ownerPage.getByRole('button', { name: 'YAML Editor', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'Open', exact: true }).click();
  await ownerPage.getByRole('button', { name: 'up -d', exact: true }).click();
  await ownerPage.getByText('Apply Compose deployment?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Apply', exact: true }).click();
  const operationsPanel = ownerPage.getByRole('region', { name: 'Supervised operations', exact: true });
  await operationsPanel.getByRole('heading', { name: 'Operation history', exact: true }).waitFor();
  await operationsPanel.getByText('Submitted run ID: ' + interactiveRun.id, { exact: true }).waitFor();
  await operationsPanel.getByRole('button', { name: 'View saved result', exact: true }).click();
  await operationsPanel.getByText('browser-interactive-private-output', { exact: true }).waitFor();
  await operationsPanel.getByRole('button', { name: 'Hide saved result', exact: true }).click();
  await operationsPanel.getByRole('button', { name: 'Inspect operation', exact: true }).click();
  await operationsPanel.getByRole('cell', { name: 'running', exact: true }).waitFor();
  await operationsPanel.getByRole('button', { name: 'Cancel operation', exact: true }).click();
  await ownerPage.getByText('Cancel operation?', { exact: true }).waitFor();
  await ownerPage.getByRole('button', { name: 'Cancel operation', exact: true }).last().click();
  await operationsPanel.getByRole('cell', { name: 'cancelled', exact: true }).waitFor();
  assert.equal(interactiveStarts, 1);
  assert.equal(interactiveInspections, 1);
  assert.equal(interactiveCancels, 1);
  await ownerPage.reload();
  await ownerPage.getByRole('button', { name: 'Operations', exact: true }).click();
  await operationsPanel.getByRole('cell', { name: 'cancelled', exact: true }).waitFor();
  assert.equal(interactiveStarts, 1);
  assert.equal(
    await operationsPanel.getByText('browser-interactive-private-output', { exact: true }).count(),
    0,
  );
  await ownerPage.unroute('**/api/features');
  response = await api(owner, '/servers/dev/tags', { tags: 'fixture-audited-change' }, 'PATCH');
  assert.equal(response.status(), 200);
  const inspectedOperationId = response.headers()['x-operation-id'];
  assert.match(inspectedOperationId, /^[a-f0-9]{32}$/);

  const viewerCodes = await enroll(viewer);
  await login(viewerPage, 'viewer', viewerCodes[0]);
  response = await api(owner, '/auth/me', undefined, 'GET');
  assert.equal(response.status(), 200);
  const ownerCodes = await enroll(owner);
  await login(ownerPage, 'owner', ownerCodes[0]);
  await ownerPage.goto(url + '/settings');
  await ownerPage.getByRole('heading', { name: 'Operation audit', exact: true }).waitFor();
  await ownerPage.getByLabel('Operation ID filter', { exact: true }).fill(inspectedOperationId);
  await ownerPage.getByRole('button', { name: 'Inspect operation', exact: true }).click();
  await ownerPage.getByRole('status').filter({ hasText: inspectedOperationId }).waitFor();
  await ownerPage.getByText(/Remote state verified: no/).waitFor();
  response = await api(owner, '/audit/operations/' + inspectedOperationId, undefined, 'GET');
  assert.equal(response.status(), 200);
  assert.equal((await response.json()).automaticRetryAllowed, false);
  await viewerPage.goto(url + '/settings');
  await viewerPage.getByText('Two-factor authentication', { exact: false }).first().waitFor();
  response = await api(viewer, '/audit/events', undefined, 'GET');
  assert.equal(response.status(), 403);
  // This fixture now performs six real admin credential changes. Preserve the
  // production five-per-minute limit and let its first budget window expire.
  const credentialWait = Math.max(0, 61000 - (Date.now() - credentialBudgetStarted));
  if (credentialWait) await new Promise((resolve) => setTimeout(resolve, credentialWait));
  response = await api(
    owner,
    '/users/' + invitation.invitation.userId,
    { currentPassword: password, status: 'disabled' },
    'PATCH',
  );
  assert.equal(response.status(), 200);
  response = await api(viewer, '/auth/me', undefined, 'GET');
  assert.equal(response.status(), 401);
  await viewerPage.goto(url + '/servers');
  await viewerPage.waitForURL('**/login');
  await ownerPage.route('**/api/auth/permissions', (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<html>Outer proxy sign in</html>' }),
  );
  await ownerPage.goto(url + '/servers');
  await ownerPage.waitForURL('**/login', { timeout: 10000 });
  console.log(
    'Chrome lab passed: signed webhook intake/secret clearing, organization runner removal/token controls, queue/review schedules, execution presets/task timing, project template/checks/commit import, GitHub runner status/removal and workflow review/draft PR, GitHub dispatch/run/job status/logs/artifacts/cancellation, YAML syntax/edit/save/assist and saved-only Compose, per-user tool visibility, scoped Ansible inventory, environment confirmation/inspection/reload without replay, accounts/MFA/scopes, stream and mutation guards, certificate renewal, supervised scheduled/interactive history/cancellation, Vault access/admin/KV, audit and proxy HTML handling.',
  );
} finally {
  await browser.close();
}
