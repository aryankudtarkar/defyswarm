import type {
  ClassifierAuditResult,
  ClassifierFileVerdict,
  GroqConfigStatus,
  GroqQuotaSnapshot,
} from '../src/shared/types.ts';

const GROQ_ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions';
export const GROQ_MODEL = 'openai/gpt-oss-120b';

// Free-tier limits for openai/gpt-oss-120b on Groq
const RPM_LIMIT = 30;
const TPM_LIMIT = 8000;
const RPD_LIMIT = 1000;
const TPD_LIMIT = 200000;

interface UsageSample {
  atMs: number;
  tokens: number;
}

export interface GeneratedCanarySpec {
  key: string;
  fileType: 'pdf' | 'docx' | 'xlsx' | 'csv' | 'txt';
  snippet: string;
}

export class GroqService {
  // Held strictly in server memory — never written to policies.yaml or returned unmasked.
  private byokApiKey: string | null = null;
  private reasoningEffort: 'low' | 'medium' = 'low';
  private canaryBatchSize = 6;
  private onboardingCompleted = false;
  private lastTestedAt?: string;
  private lastTestOk?: boolean;
  private cooldownUntilMs = 0;

  private usageLog: UsageSample[] = [];
  private lastCallTokens?: number;
  private lastCallAt?: string;

  private getActiveKey(): { key: string | null; source: 'byok' | 'env' | 'none' } {
    if (this.byokApiKey && this.byokApiKey.trim().length > 0) {
      return { key: this.byokApiKey.trim(), source: 'byok' };
    }
    const envKey = process.env.GROQ_API_KEY?.trim();
    if (envKey && envKey.length > 0) {
      return { key: envKey, source: 'env' };
    }
    return { key: null, source: 'none' };
  }

  private maskKey(key: string | null): string | null {
    if (!key) return null;
    if (key.length <= 8) return '••••••••';
    return `${key.slice(0, 4)}••••${key.slice(-4)}`;
  }

  public setByokKey(key: string | null) {
    this.byokApiKey = key && key.trim().length > 0 ? key.trim() : null;
    if (this.byokApiKey) {
      this.onboardingCompleted = true;
    }
  }

  public updatePreferences(opts: {
    reasoningEffort?: 'low' | 'medium';
    canaryBatchSize?: number;
    onboardingCompleted?: boolean;
  }) {
    if (opts.reasoningEffort === 'low' || opts.reasoningEffort === 'medium') {
      this.reasoningEffort = opts.reasoningEffort;
    }
    if (typeof opts.canaryBatchSize === 'number') {
      this.canaryBatchSize = Math.max(3, Math.min(8, Math.round(opts.canaryBatchSize)));
    }
    if (typeof opts.onboardingCompleted === 'boolean') {
      this.onboardingCompleted = opts.onboardingCompleted;
    }
  }

  private pruneUsage(nowMs: number) {
    const dayAgo = nowMs - 24 * 60 * 60 * 1000;
    this.usageLog = this.usageLog.filter((u) => u.atMs >= dayAgo);
  }

  public getQuotaSnapshot(): GroqQuotaSnapshot {
    const nowMs = Date.now();
    this.pruneUsage(nowMs);
    const minAgo = nowMs - 60 * 1000;

    let rpmUsed = 0;
    let tpmUsed = 0;
    let rpdUsed = 0;
    let tpdUsed = 0;

    for (const u of this.usageLog) {
      rpdUsed += 1;
      tpdUsed += u.tokens;
      if (u.atMs >= minAgo) {
        rpmUsed += 1;
        tpmUsed += u.tokens;
      }
    }

    const cooldownSecondsRemaining =
      this.cooldownUntilMs > nowMs ? Math.ceil((this.cooldownUntilMs - nowMs) / 1000) : 0;

    return {
      model: GROQ_MODEL,
      rpmLimit: RPM_LIMIT,
      rpmUsed,
      tpmLimit: TPM_LIMIT,
      tpmUsed,
      rpdLimit: RPD_LIMIT,
      rpdUsed,
      tpdLimit: TPD_LIMIT,
      tpdUsed,
      cooldownSecondsRemaining,
      lastCallTokens: this.lastCallTokens,
      lastCallAt: this.lastCallAt,
    };
  }

  public getStatus(): GroqConfigStatus {
    const active = this.getActiveKey();
    return {
      configured: active.key !== null,
      source: active.source,
      maskedKey: this.maskKey(active.key),
      model: GROQ_MODEL,
      reasoningEffort: this.reasoningEffort,
      canaryBatchSize: this.canaryBatchSize,
      onboardingCompleted: this.onboardingCompleted || active.source === 'env',
      lastTestedAt: this.lastTestedAt,
      lastTestOk: this.lastTestOk,
      quota: this.getQuotaSnapshot(),
    };
  }

  private checkFreeTierBudget(estimatedTokens: number) {
    const quota = this.getQuotaSnapshot();
    if (quota.cooldownSecondsRemaining > 0) {
      throw new Error(
        `Groq free-tier cooldown active (${quota.cooldownSecondsRemaining}s remaining). Wait briefly before retrying.`,
      );
    }
    if (quota.rpmUsed >= RPM_LIMIT) {
      this.cooldownUntilMs = Date.now() + 15000;
      throw new Error(`Groq free-tier RPM budget reached (${quota.rpmUsed}/${RPM_LIMIT} req/min).`);
    }
    if (quota.tpmUsed + estimatedTokens > TPM_LIMIT) {
      const oldestInMin = this.usageLog.find((u) => u.atMs >= Date.now() - 60000);
      const waitSec = oldestInMin
        ? Math.max(5, Math.ceil((oldestInMin.atMs + 60000 - Date.now()) / 1000))
        : 20;
      this.cooldownUntilMs = Date.now() + waitSec * 1000;
      throw new Error(
        `Free-tier TPM safeguard: ${quota.tpmUsed}/${TPM_LIMIT} tokens used this minute (need ~${estimatedTokens}). Ready in ${waitSec}s.`,
      );
    }
    if (quota.rpdUsed >= RPD_LIMIT || quota.tpdUsed + estimatedTokens > TPD_LIMIT) {
      throw new Error(
        `Groq daily free-tier limit reached (${quota.tpdUsed}/${TPD_LIMIT} tokens/day).`,
      );
    }
  }

  private async callGroqChat(params: {
    systemPrompt: string;
    userPrompt: string;
    maxCompletionTokens: number;
    estimatedTokens: number;
    overrideKey?: string;
    expectJson?: boolean;
  }): Promise<{ content: string; totalTokens: number }> {
    const apiKey = params.overrideKey?.trim() || this.getActiveKey().key;
    if (!apiKey) {
      throw new Error(
        'No AI provider key configured. Add an API key in Settings → AI Analysis to enable AI features.',
      );
    }

    this.checkFreeTierBudget(params.estimatedTokens);

    const body: Record<string, unknown> = {
      model: GROQ_MODEL,
      messages: [
        { role: 'system', content: params.systemPrompt },
        { role: 'user', content: params.userPrompt },
      ],
      max_completion_tokens: params.maxCompletionTokens,
      reasoning_effort: this.reasoningEffort,
    };

    if (params.expectJson) {
      body.response_format = { type: 'json_object' };
    }

    const res = await fetch(GROQ_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (res.status === 429) {
      const retryAfter = Number(res.headers.get('retry-after') || '20');
      const waitSec = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.ceil(retryAfter) : 20;
      this.cooldownUntilMs = Date.now() + waitSec * 1000;
      throw new Error(
        `Groq free-tier rate limit reached (HTTP 429). Cooldown set for ${waitSec}s (8,000 TPM / 30 RPM cap).`,
      );
    }

    if (res.status === 401 || res.status === 403) {
      throw new Error(
        'Groq rejected the API key (HTTP 401). Verify your gsk_... key in Setup → LLM Provider.',
      );
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => res.statusText);
      throw new Error(`Groq API error (HTTP ${res.status}): ${errText.slice(0, 220)}`);
    }

    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { total_tokens?: number };
    };

    const content = data.choices?.[0]?.message?.content?.trim();
    if (!content) {
      throw new Error('Groq returned an empty completion response.');
    }

    const totalTokens = data.usage?.total_tokens ?? params.estimatedTokens;
    const nowMs = Date.now();
    this.usageLog.push({ atMs: nowMs, tokens: totalTokens });
    this.lastCallTokens = totalTokens;
    this.lastCallAt = new Date(nowMs).toISOString();

    return { content, totalTokens };
  }

  public async testConnection(overrideKey?: string): Promise<{ ok: boolean; latencyMs: number; tokensUsed: number; message: string }> {
    const start = Date.now();
    try {
      const result = await this.callGroqChat({
        systemPrompt: 'Reply with compact JSON {"ok":true}.',
        userPrompt: 'Ping',
        maxCompletionTokens: 64,
        estimatedTokens: 80,
        overrideKey,
        expectJson: true,
      });
      this.lastTestedAt = new Date().toISOString();
      this.lastTestOk = true;
      return {
        ok: true,
        latencyMs: Date.now() - start,
        tokensUsed: result.totalTokens,
        message: `Connected to Groq (${GROQ_MODEL}) in ${Date.now() - start} ms.`,
      };
    } catch (err) {
      this.lastTestedAt = new Date().toISOString();
      this.lastTestOk = false;
      throw err;
    }
  }

  /**
   * Single-call token-budgeted adaptive canary generation (~2,000 tokens total — safe inside 8,000 TPM).
   */
  public async generateAdaptiveCanaries(
    bucket: string,
    existingSampleKeys: string[],
    countOverride?: number,
  ): Promise<{ specs: GeneratedCanarySpec[]; tokensUsed: number }> {
    const count = Math.max(3, Math.min(8, countOverride ?? this.canaryBatchSize));
    const sampleList = existingSampleKeys.slice(0, 14).join('\n');

    const systemPrompt =
      'You are DefySwarm Canary Architect. Generate realistic decoy file paths and brief synthetic business document excerpts that blend seamlessly into an enterprise object-storage bucket so AI ransomware agents cannot distinguish them from real files. Never use words like canary, trap, decoy, test, fake, honeypot, or 000_. Output strict JSON only: {"canaries":[{"key":"path/file.ext","fileType":"pdf|docx|xlsx|csv|txt","snippet":"2-3 sentence realistic synthetic business content"}]}.';

    const userPrompt = `Bucket: ${bucket}\nExisting tenant object paths (match naming style, dates, folder depth 2-3, and extensions):\n${sampleList}\n\nGenerate exactly ${count} unique adaptive decoy objects.`;

    const { content, totalTokens } = await this.callGroqChat({
      systemPrompt,
      userPrompt,
      maxCompletionTokens: 1600,
      estimatedTokens: 2100,
      expectJson: true,
    });

    const parsed = safeParseJson(content) as { canaries?: Array<Record<string, unknown>> };
    const rawList = Array.isArray(parsed.canaries) ? parsed.canaries : [];
    const allowedTypes = new Set(['pdf', 'docx', 'xlsx', 'csv', 'txt']);

    const specs: GeneratedCanarySpec[] = rawList
      .map((item) => {
        const key = String(item.key || '').replace(/^\/+/, '').trim();
        const rawType = String(item.fileType || 'pdf').toLowerCase();
        const fileType = (allowedTypes.has(rawType) ? rawType : 'pdf') as GeneratedCanarySpec['fileType'];
        const snippet = String(item.snippet || 'Quarterly operating reconciliation summary.').trim();
        return { key, fileType, snippet };
      })
      .filter((s) => s.key.length > 3 && !s.key.includes('..'));

    if (specs.length === 0) {
      throw new Error('Model returned no valid canary entries. Try again.');
    }

    return { specs, tokensUsed: totalTokens };
  }

  /**
   * Single-batch 10-file blind canary-vs-real classifier evaluation (~2,300 tokens total — safe inside 8,000 TPM).
   */
  public async runBlindClassifierAudit(
    samples: Array<{
      key: string;
      sizeBytes: number;
      fileType: string;
      excerpt: string;
      actualLabel: 'canary' | 'real';
    }>,
  ): Promise<ClassifierAuditResult> {
    // Shuffle deterministically-random so order gives zero hints
    const shuffled = [...samples].sort(() => Math.random() - 0.5).slice(0, 10);

    const blindPayload = shuffled.map((s, idx) => ({
      id: idx + 1,
      path: s.key,
      sizeBytes: s.sizeBytes,
      type: s.fileType,
      excerpt: s.excerpt.slice(0, 220),
    }));

    const systemPrompt =
      'You are an adversarial AI agent inspecting cloud storage files to avoid ransomware decoys. Half the files are real corporate documents and half are decoy canaries. Classify each item as "canary" or "real" based ONLY on path, size, type, and excerpt. Output strict JSON: {"verdicts":[{"id":1,"prediction":"canary"|"real","confidence":0.0-1.0,"reason":"max 12 words"}]}.';

    const userPrompt = `Classify these ${blindPayload.length} storage objects:\n${JSON.stringify(blindPayload)}`;

    const { content, totalTokens } = await this.callGroqChat({
      systemPrompt,
      userPrompt,
      maxCompletionTokens: 1200,
      estimatedTokens: 2300,
      expectJson: true,
    });

    const parsed = safeParseJson(content) as { verdicts?: Array<Record<string, unknown>> };
    const rawVerdicts = Array.isArray(parsed.verdicts) ? parsed.verdicts : [];

    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;

    const verdicts: ClassifierFileVerdict[] = shuffled.map((sample, idx) => {
      const found = rawVerdicts.find((v) => Number(v.id) === idx + 1);
      const predRaw = String(found?.prediction || 'real').toLowerCase();
      const predictedLabel: 'canary' | 'real' = predRaw === 'canary' ? 'canary' : 'real';
      const correct = predictedLabel === sample.actualLabel;

      if (sample.actualLabel === 'canary' && predictedLabel === 'canary') tp++;
      else if (sample.actualLabel === 'real' && predictedLabel === 'canary') fp++;
      else if (sample.actualLabel === 'real' && predictedLabel === 'real') tn++;
      else fn++;

      return {
        key: sample.key,
        actualLabel: sample.actualLabel,
        predictedLabel,
        correct,
        confidence: Number(Math.min(1, Math.max(0.5, Number(found?.confidence ?? 0.62))).toFixed(2)),
        reasoning: String(found?.reason || 'Evaluated naming pattern and document structure.').slice(0, 120),
      };
    });

    const correctCount = tp + tn;
    const accuracyPct = Number(((correctCount / Math.max(1, verdicts.length)) * 100).toFixed(1));

    return {
      id: `clf-${Date.now()}`,
      runAt: new Date().toISOString(),
      model: GROQ_MODEL,
      sampleSize: verdicts.length,
      canaryCount: shuffled.filter((s) => s.actualLabel === 'canary').length,
      realCount: shuffled.filter((s) => s.actualLabel === 'real').length,
      correctCount,
      accuracyPct,
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      tokensUsed: totalTokens,
      verdicts,
    };
  }
}

function safeParseJson(text: string): Record<string, unknown> {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed) as Record<string, unknown>;
  } catch {
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start >= 0 && end > start) {
      return JSON.parse(trimmed.slice(start, end + 1)) as Record<string, unknown>;
    }
    throw new Error('Could not parse structured JSON from Groq response.');
  }
}
