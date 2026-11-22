import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import { WebSocket, WebSocketServer } from 'ws';
import type { Role, SimScenarioId } from './src/shared/types.ts';
import { DefySwarmStateStore } from './server/stateStore.ts';

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

async function startServer() {
  const app = express();
  app.use('/api', (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws/live' });
  const state = new DefySwarmStateStore();

  const broadcast = (type: string, payload: unknown) => {
    const message = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  };
  state.setBroadcaster(broadcast);

  wss.on('connection', (socket) => {
    socket.send(
      JSON.stringify({
        type: 'snapshot',
        payload: state.getBootstrapState(),
        timestamp: new Date().toISOString(),
      }),
    );
  });

  // Periodic health heartbeat every 5s
  setInterval(() => {
    broadcast('health:update', {
      health: state.getHealthMetrics(),
      groq: state.groq.getStatus(),
      vault: state.store.getVaultStatus(),
    });
  }, 5000);

  // Extract and validate RBAC role header
  const parseRole = (req: express.Request): Role => {
    const raw = String(req.headers['x-defyswarm-role'] || 'admin').toLowerCase();
    if (raw === 'viewer' || raw === 'operator' || raw === 'admin') return raw;
    return 'viewer';
  };

  const requireRole = (allowed: Role[]) => {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
      const role = parseRole(req);
      if (!allowed.includes(role)) {
        state.recordAudit(
          role,
          `${req.method} ${req.path}`,
          'rbac-guard',
          'denied',
          `Role "${role}" denied access; requires ${allowed.join(' or ')}.`,
        );
        res.status(403).json({
          error: `Permission denied for role "${role}". Switch to ${allowed.join(' or ')} to perform this action.`,
        });
        return;
      }
      next();
    };
  };

  // --- Raw Binary Live Object Upload Route (before express.json so real files & curl --data-binary work) ---
  app.post(
    '/api/storage/objects',
    express.raw({ type: () => true, limit: '10mb' }),
    async (req, res) => {
      // Allow either console operator/admin role OR valid external ingest token (for curl CLI)
      const hasToken = state.verifyIngestAuth({
        headerToken: req.headers['x-defyswarm-token'] as string | undefined,
        authHeader: req.headers.authorization,
      });
      const role = parseRole(req);
      if (!hasToken && role === 'viewer') {
        res.status(403).json({
          error: 'Viewer role cannot upload objects. Switch to Operator/Admin or pass X-DefySwarm-Token.',
        });
        return;
      }

      const bucket = String(req.headers['x-defyswarm-bucket'] || req.query.bucket || 'finance-prod');
      const key = String(req.headers['x-defyswarm-key'] || req.query.key || '');
      const principalId = String(
        req.headers['x-defyswarm-principal'] || req.query.principal || 'svc-billing-etl',
      );
      const contentType = String(req.headers['content-type'] || 'application/octet-stream');
      const sseAlgorithm = req.headers['x-defyswarm-sse']
        ? String(req.headers['x-defyswarm-sse'])
        : undefined;
      const kmsKeyId = req.headers['x-defyswarm-kms']
        ? String(req.headers['x-defyswarm-kms'])
        : undefined;

      if (!key.trim()) {
        res.status(400).json({ error: 'Object key is required (header x-defyswarm-key or query ?key=).' });
        return;
      }

      const rawBuffer = Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from(typeof req.body === 'string' ? req.body : '');

      if (rawBuffer.length === 0) {
        res.status(400).json({ error: 'Upload payload is empty. Send raw file bytes.' });
        return;
      }

      try {
        const result = await state.handleLivePutObject({
          bucket,
          key,
          buffer: rawBuffer,
          principalId,
          contentType,
          sseAlgorithm,
          kmsKeyId,
        });
        if (result.httpStatus === 403) {
          res.status(403).json({
            ok: false,
            httpStatus: 403,
            error: result.error,
            event: result.event,
          });
          return;
        }
        res.status(result.httpStatus).json({ ok: true, ...result });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : 'Upload failed.' });
      }
    },
  );

  // --- Authenticated External S3 / MinIO Webhook Receiver (preserves raw body for HMAC verification) ---
  app.post(
    '/api/ingest/s3-event',
    express.raw({ type: () => true, limit: '2mb' }),
    async (req, res) => {
      const rawBuf = Buffer.isBuffer(req.body) ? req.body : Buffer.from('');
      const authorized = state.verifyIngestAuth({
        headerToken: req.headers['x-defyswarm-token'] as string | undefined,
        authHeader: req.headers.authorization,
        hmacSignature: req.headers['x-defyswarm-signature'] as string | undefined,
        rawBody: rawBuf,
      });

      if (!authorized) {
        state.recordAudit(
          'viewer',
          'ingest.webhook_rejected',
          '/api/ingest/s3-event',
          'denied',
          'Rejected unauthenticated external S3/MinIO webhook call.',
        );
        res.status(401).json({
          error: 'Unauthorized webhook. Pass valid X-DefySwarm-Token, Bearer token, or X-DefySwarm-Signature.',
        });
        return;
      }

      try {
        const parsed = JSON.parse(rawBuf.toString('utf8') || '{}');
        const result = await state.processExternalS3Webhook(parsed);
        res.json({ ok: true, ...result });
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid S3 event payload.' });
      }
    },
  );

  // Standard JSON parser for all remaining control-plane REST routes
  app.use(express.json({ limit: '2mb' }));

  // --- REST API Routes ---

  app.get('/api/bootstrap', (_req, res) => {
    res.json(state.getBootstrapState());
  });

  // Live Storage Browser & Real Object Operations
  app.get('/api/storage/objects', async (req, res) => {
    const bucket = String(req.query.bucket || 'finance-prod');
    try {
      const objects = await state.listLiveObjects(bucket);
      res.json({ ok: true, bucket, objects });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Could not list objects.' });
    }
  });

  app.get('/api/storage/objects/download', async (req, res) => {
    const bucket = String(req.query.bucket || 'finance-prod');
    const key = String(req.query.key || '');
    const fromVault = String(req.query.fromVault || 'false') === 'true';
    try {
      const file = await state.getObjectForDownload(bucket, key, fromVault);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-DefySwarm-SHA256', file.sha256);
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${file.filename.replace(/[^a-zA-Z0-9._-]/g, '_')}"`,
      );
      res.send(file.buffer);
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'Object not found.' });
    }
  });

  app.post('/api/storage/objects/encrypt-test', requireRole(['operator', 'admin']), async (req, res) => {
    const { bucket, key, principalId } = req.body as {
      bucket?: string;
      key?: string;
      principalId?: string;
    };
    if (!bucket || !key) {
      res.status(400).json({ error: 'bucket and key are required.' });
      return;
    }
    try {
      const result = await state.handleRealEncryptedOverwriteTest({
        bucket,
        key,
        principalId: principalId || 'svc-billing-etl',
      });
      if (result.httpStatus === 403) {
        res.status(403).json({ ok: false, ...result });
        return;
      }
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Encrypted overwrite test failed.' });
    }
  });

  app.delete('/api/storage/objects', async (req, res) => {
    const hasToken = state.verifyIngestAuth({
      headerToken: req.headers['x-defyswarm-token'] as string | undefined,
      authHeader: req.headers.authorization,
    });
    const role = parseRole(req);
    if (!hasToken && role === 'viewer') {
      res.status(403).json({ error: 'Viewer role cannot delete objects.' });
      return;
    }
    const bucket = String(req.query.bucket || 'finance-prod');
    const key = String(req.query.key || '');
    const principalId = String(
      req.headers['x-defyswarm-principal'] || req.query.principal || 'svc-billing-etl',
    );
    try {
      const result = await state.handleLiveDeleteObject({ bucket, key, principalId });
      if (result.httpStatus === 403) {
        res.status(403).json({ ok: false, ...result });
        return;
      }
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Delete failed.' });
    }
  });

  // Manual principal status control (Quarantine / Restore access)
  app.post('/api/principals/:id/status', requireRole(['operator', 'admin']), (req, res) => {
    const role = parseRole(req);
    const { status } = req.body as { status?: 'ACTIVE' | 'REVOKED' };
    if (status !== 'ACTIVE' && status !== 'REVOKED') {
      res.status(400).json({ error: 'status must be ACTIVE or REVOKED.' });
      return;
    }
    try {
      const updated = state.setPrincipalStatus(req.params.id, status, role);
      res.json({ ok: true, principal: updated });
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'Principal not found.' });
    }
  });

  // Ingest Token, Self-Test Webhook & Poller Controls
  app.post('/api/settings/ingest/reveal', requireRole(['admin']), (_req, res) => {
    res.json({ ok: true, token: state.getIngestTokenForAdmin() });
  });

  app.post('/api/settings/ingest/rotate', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    const token = state.rotateIngestToken(role);
    res.json({ ok: true, token, ingest: state.getIngestStatus() });
  });

  app.post('/api/settings/ingest/test', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    const bucket = String((req.body as { bucket?: string }).bucket || state.storageSettings.productionBucket || 'finance-prod');
    const result = await state.processExternalS3Webhook({
      Records: [
        {
          eventName: 's3:ObjectCreated:Put',
          eventTime: new Date().toISOString(),
          userIdentity: { principalId: 'webhook-selftest-client' },
          s3: {
            bucket: { name: bucket },
            object: { key: 'finance/2026/Q3/webhook_health_check.csv', size: 1024 },
          },
        },
      ],
    });
    state.recordAudit(
      role,
      'ingest.webhook_selftest',
      bucket,
      'success',
      `Verified authenticated S3 webhook ingestion pipeline (${result.processed} event processed).`,
    );
    res.json({ ok: true, ...result });
  });

  app.post('/api/ingest/poll-now', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    try {
      const result = await state.pollExternalBucketNow(role);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Polling failed.' });
    }
  });

  app.post('/api/settings/containment', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    try {
      const ingest = state.updateContainmentWebhook(req.body, role);
      res.json({ ok: true, ingest });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Containment config failed.' });
    }
  });

  // Policy & Setup
  app.put('/api/policy', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    const { yaml } = req.body as { yaml?: string };
    if (typeof yaml !== 'string') {
      res.status(400).json({ error: 'Request body must include "yaml" string.' });
      return;
    }
    const result = state.updatePolicyFromYaml(yaml, role);
    if (!result.valid) {
      res.status(400).json({ error: 'Policy validation failed.', errors: result.errors });
      return;
    }
    res.json({ ok: true, policy: state.policy, policyYaml: state.policyYaml });
  });

  app.post('/api/policy/mode', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    const { mode } = req.body as { mode?: 'active' | 'dry-run' };
    if (mode !== 'active' && mode !== 'dry-run') {
      res.status(400).json({ error: 'Mode must be "active" or "dry-run".' });
      return;
    }
    state.updateMode(mode, role);
    res.json({ ok: true, mode });
  });

  app.post('/api/policy/allowlist', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    const { principals, kmsKeys } = req.body as { principals?: string[]; kmsKeys?: string[] };
    if (!Array.isArray(principals) || !Array.isArray(kmsKeys)) {
      res.status(400).json({ error: 'principals and kmsKeys arrays are required.' });
      return;
    }
    state.updateAllowlist(principals, kmsKeys, role);
    res.json({ ok: true, allowlist: state.policy.allowlist });
  });

  app.post('/api/buckets', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    const { name, sensitivity, simOnly, vault } = req.body as {
      name?: string;
      sensitivity?: 'critical' | 'sandbox';
      simOnly?: boolean;
      vault?: string;
    };
    try {
      state.registerOrUpdateBucket(
        {
          name: String(name || ''),
          sensitivity: sensitivity === 'sandbox' ? 'sandbox' : 'critical',
          simOnly: Boolean(simOnly),
          vault: String(vault || 'vault-finance'),
        },
        role,
      );
      res.json({ ok: true, buckets: Array.from(state.store.buckets.values()) });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid bucket.' });
    }
  });

  app.post('/api/buckets/:name/harden', requireRole(['admin', 'operator']), (req, res) => {
    const role = parseRole(req);
    try {
      const result = state.runAutoHarden(req.params.name, role);
      res.json(result);
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'Bucket not found.' });
    }
  });

  app.post('/api/settings/storage', requireRole(['admin']), async (req, res) => {
    const role = parseRole(req);
    try {
      const updated = await state.testAndSaveStorageSettings(req.body, role);
      res.json({ ok: true, storage: updated });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Storage configuration failed.' });
    }
  });

  app.post('/api/settings/alerts', requireRole(['admin']), (req, res) => {
    const role = parseRole(req);
    try {
      const updated = state.updateAlertSettings(req.body, role);
      res.json({ ok: true, alerts: updated });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Alert configuration failed.' });
    }
  });

  app.post('/api/settings/alerts/test', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    try {
      const result = await state.sendTestAlert(role);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Test alert failed.' });
    }
  });

  // Groq BYOK Onboarding & Settings
  app.post('/api/settings/llm', (req, res) => {
    const role = parseRole(req);
    const { apiKey, clearKey, reasoningEffort, canaryBatchSize, onboardingCompleted } = req.body as {
      apiKey?: string;
      clearKey?: boolean;
      reasoningEffort?: 'low' | 'medium';
      canaryBatchSize?: number;
      onboardingCompleted?: boolean;
    };

    const isInitialOnboarding = !state.groq.getStatus().onboardingCompleted;
    if (!isInitialOnboarding && role !== 'admin') {
      res.status(403).json({ error: 'Only Admin role can modify LLM provider settings after onboarding.' });
      return;
    }

    if (clearKey) {
      state.groq.setByokKey(null);
      state.recordAudit(role, 'llm.key_cleared', 'ai-analysis', 'success', 'Cleared AI provider API key from active session.');
    } else if (typeof apiKey === 'string' && apiKey.trim().length > 0) {
      state.groq.setByokKey(apiKey.trim());
      state.recordAudit(role, 'llm.key_saved', 'ai-analysis', 'success', 'Updated AI analysis provider credentials.');
    }

    state.groq.updatePreferences({ reasoningEffort, canaryBatchSize, onboardingCompleted });
    state.persistLedger();
    state.emitStateSync();
    res.json({ ok: true, groq: state.groq.getStatus() });
  });

  app.post('/api/settings/llm/test', async (req, res) => {
    const role = parseRole(req);
    const isInitialOnboarding = !state.groq.getStatus().onboardingCompleted;
    if (!isInitialOnboarding && role === 'viewer') {
      res.status(403).json({ error: 'Viewer role cannot execute outbound LLM connection tests.' });
      return;
    }
    const { apiKey } = req.body as { apiKey?: string };
    try {
      const result = await state.groq.testConnection(apiKey);
      state.recordAudit(role, 'llm.connection_test', 'openai/gpt-oss-120b', 'success', result.message);
      state.emitStateSync();
      res.json({ ...result, groq: state.groq.getStatus() });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Groq connection test failed.';
      state.recordAudit(role, 'llm.connection_test', 'openai/gpt-oss-120b', 'error', msg);
      state.emitStateSync();
      res.status(400).json({ ok: false, error: msg, groq: state.groq.getStatus() });
    }
  });

  // Simulator & Reset Demo
  app.post('/api/simulator/run', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    const { scenario, bucket } = req.body as { scenario?: SimScenarioId; bucket?: string };
    if (!scenario || !bucket) {
      res.status(400).json({ error: 'scenario and bucket are required.' });
      return;
    }

    const lock = state.runner.verifyBlastRadiusLock(bucket);
    if (!lock.allowed) {
      state.recordAudit(role, 'simulator.blocked', bucket, 'denied', lock.reason);
      res.status(403).json({ error: lock.reason });
      return;
    }

    state.recordAudit(role, 'simulator.run', `${bucket}:${scenario}`, 'success', `Launched simulator scenario ${scenario} on ${bucket}.`);

    state.runner
      .runScenario(scenario, bucket)
      .then(() => {
        state.persistLedger();
        state.emitStateSync();
      })
      .catch((err) => {
        state.recordAudit(
          role,
          'simulator.error',
          bucket,
          'error',
          err instanceof Error ? err.message : 'Simulation failed.',
        );
      });

    res.json({ ok: true, started: true, scenario, bucket });
  });

  app.post('/api/simulator/admin-gate-test', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    const bucket = String((req.body as { bucket?: string }).bucket || 'finance-prod');
    await state.triggerHumanAdminTestScenario(bucket, role);
    res.json({ ok: true });
  });

  app.post('/api/simulator/reset', requireRole(['operator', 'admin']), (req, res) => {
    const role = parseRole(req);
    state.resetDemo(role);
    res.json({ ok: true, state: state.getBootstrapState() });
  });

  // Incidents & 1-Click Restore
  app.get('/api/incidents/:id/restore-preview', (req, res) => {
    try {
      const preview = state.engine.buildRestorePreview(req.params.id);
      res.json(preview);
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'Incident not found.' });
    }
  });

  app.post('/api/incidents/:id/restore', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    try {
      const { incident, report } = await state.executeOneClickRestoreWithExternalSync(req.params.id, role);
      res.json({ ok: true, incident, report });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Restore failed.' });
    }
  });

  app.post('/api/incidents/:id/approve-admin', requireRole(['operator', 'admin']), (req, res) => {
    const role = parseRole(req);
    const { decision } = req.body as { decision?: 'approved' | 'denied' };
    if (decision !== 'approved' && decision !== 'denied') {
      res.status(400).json({ error: 'decision must be "approved" or "denied".' });
      return;
    }
    try {
      const inc = state.engine.approveOrDenyAdminQuarantine(req.params.id, decision, role);
      state.recordAudit(
        role,
        'incident.admin_decision',
        inc.id,
        'success',
        `Human-admin quarantine ${decision} for ${inc.pendingAdminApproval?.principalId}.`,
      );
      state.persistLedger();
      state.emitStateSync();
      res.json({ ok: true, incident: inc });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Approval update failed.' });
    }
  });

  app.get('/api/incidents/:id/export', (req, res) => {
    const inc = state.engine.incidents.find((i) => i.id === req.params.id);
    if (!inc) {
      res.status(404).json({ error: 'Incident not found.' });
      return;
    }
    const safeId = inc.id.replace(/[^a-zA-Z0-9._-]/g, '_');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="defyswarm-forensic-${safeId}.json"`);
    res.send(
      JSON.stringify(
        {
          exportedAt: new Date().toISOString(),
          product: 'DefySwarm',
          adapter: state.storageSettings.provider,
          incident: inc,
          vaultStatus: state.store.getVaultStatus(),
        },
        null,
        2,
      ),
    );
  });

  // Canaries & Groq Classifier
  app.post('/api/canaries/refresh', requireRole(['operator', 'admin']), (req, res) => {
    const role = parseRole(req);
    const bucket = String((req.body as { bucket?: string }).bucket || 'finance-prod');
    const count = state.refreshCanaries(bucket, role);
    res.json({ ok: true, refreshedCount: count });
  });

  app.post('/api/canaries/generate', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    const bucket = String((req.body as { bucket?: string }).bucket || 'finance-prod');
    try {
      const result = await state.generateCanariesWithGroq(bucket, role);
      res.json({ ok: true, ...result, groq: state.groq.getStatus() });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Groq canary generation failed.';
      state.recordAudit(role, 'canaries.generate_llm', bucket, 'error', msg);
      res.status(400).json({ error: msg, groq: state.groq.getStatus() });
    }
  });

  app.post('/api/canaries/classify', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    const bucket = String((req.body as { bucket?: string }).bucket || 'finance-prod');
    try {
      const audit = await state.runCanaryClassifierAudit(bucket, role);
      res.json({ ok: true, audit, groq: state.groq.getStatus() });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Groq classifier test failed.';
      state.recordAudit(role, 'canaries.classifier_test', bucket, 'error', msg);
      res.status(400).json({ error: msg, groq: state.groq.getStatus() });
    }
  });

  // 30-Run Benchmark Harness
  app.post('/api/benchmarks/run', requireRole(['operator', 'admin']), async (req, res) => {
    const role = parseRole(req);
    const rawIter = Number((req.body as { iterations?: number }).iterations ?? 30);
    const iterations = Number.isFinite(rawIter) ? Math.max(1, Math.min(50, Math.round(rawIter))) : 30;
    try {
      const result = await state.runner.runBenchmarkSuite(iterations);
      state.benchmarks.unshift(result);
      if (state.benchmarks.length > 20) state.benchmarks.length = 20;
      state.recordAudit(
        role,
        'benchmark.run',
        result.id,
        'success',
        `Completed ${result.iterationsPerScenario}-run benchmark suite in ${result.durationMs} ms (overallPass=${result.overallPass}).`,
      );
      state.persistLedger();
      state.emitStateSync();
      res.json({ ok: true, benchmark: result });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Benchmark failed.' });
    }
  });

  // Health & Stream-Gap Diagnostic
  app.post('/api/health/stream-gap', requireRole(['operator', 'admin']), (req, res) => {
    const role = parseRole(req);
    const { simulated } = req.body as { simulated?: boolean };
    state.streamGapSimulated = Boolean(simulated);
    state.recordAudit(
      role,
      'health.stream_gap_toggle',
      'event-ingestion',
      'success',
      state.streamGapSimulated
        ? 'Simulated ingestion stream gap to verify degraded alert banner.'
        : 'Restored real-time event ingestion stream.',
    );
    state.emitStateSync();
    res.json({ ok: true, health: state.getHealthMetrics() });
  });

  // Mount Vite middleware in dev or serve built dist/ in production
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`DefySwarm control plane listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start DefySwarm server:', err);
  process.exit(1);
});
