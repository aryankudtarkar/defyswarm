import {
  DeleteObjectCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  GetObjectLockConfigurationCommand,
  HeadBucketCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import type { StorageProviderPreset } from '../src/shared/types.ts';
import { computeShannonEntropy, inspectMagicHeader, sha256Hex } from './cryptoUtils.ts';
import { validateSafeExternalUrl } from './storageAdapter.ts';

export interface ExternalS3Credentials {
  accessKeyId: string;
  secretAccessKey: string;
}

export interface ExternalS3Config {
  provider: StorageProviderPreset;
  endpoint: string;
  region: string;
  forcePathStyle: boolean;
  productionBucket: string;
  vaultBucket: string;
}

export interface ExternalBucketPosture {
  reachable: boolean;
  versioningStatus: 'Enabled' | 'Suspended' | 'Disabled' | 'Unknown';
  objectLockEnabled: boolean;
  vaultReachable: boolean;
  message: string;
}

export interface ExternalObjectItem {
  key: string;
  sizeBytes: number;
  etag: string;
  lastModified: string;
}

export interface ExternalRangeInspection {
  buffer: Buffer;
  entropy: number;
  magicValid: boolean;
  magicDetected: string;
  sha256Prefix: string;
  contentLength: number;
}

export interface PollDiffItem {
  bucket: string;
  key: string;
  kind: 'created' | 'modified' | 'deleted';
  etag: string;
  sizeBytes: number;
  prevEntropy?: number;
  inspection?: ExternalRangeInspection;
}

async function streamToBuffer(body: unknown, maxBytes: number): Promise<Buffer> {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body.subarray(0, maxBytes);
  if (body instanceof Uint8Array) return Buffer.from(body.subarray(0, maxBytes));

  // AWS SDK v3 Node Readable or transformToByteArray
  const maybeTransform = body as { transformToByteArray?: () => Promise<Uint8Array> };
  if (typeof maybeTransform.transformToByteArray === 'function') {
    const arr = await maybeTransform.transformToByteArray();
    return Buffer.from(arr.subarray(0, maxBytes));
  }

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of body as AsyncIterable<Uint8Array | Buffer | string>) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = maxBytes - total;
    if (remaining <= 0) break;
    chunks.push(buf.length > remaining ? buf.subarray(0, remaining) : buf);
    total += Math.min(buf.length, remaining);
    if (total >= maxBytes) break;
  }
  return Buffer.concat(chunks);
}

/**
 * Real S3-compatible client adapter for 100% free, zero-credit-card object storage:
 * Backblaze B2 (10 GB free), Supabase Storage S3 (1 GB free), Self-Hosted MinIO, or any S3-compatible endpoint.
 * Secrets stay strictly in server memory or process.env — never serialized to disk.
 */
export class ExternalS3Adapter {
  private monitorCreds: ExternalS3Credentials | null = null;
  private vaultCreds: ExternalS3Credentials | null = null;
  private config: ExternalS3Config = {
    provider: 'local',
    endpoint: 'https://s3.us-west-004.backblazeb2.com',
    region: 'us-west-004',
    forcePathStyle: true,
    productionBucket: 'finance-prod',
    vaultBucket: 'vault-finance',
  };

  // ETag + entropy baseline cache for quota-safe background polling
  private etagCache = new Map<string, { etag: string; size: number; entropy: number; seeded: boolean }>();
  private apiCallsToday = 0;
  private apiCallsDayKey = new Date().toISOString().slice(0, 10);

  constructor() {
    if (process.env.S3_ACCESS_KEY_ID && process.env.S3_SECRET_ACCESS_KEY) {
      this.monitorCreds = {
        accessKeyId: process.env.S3_ACCESS_KEY_ID.trim(),
        secretAccessKey: process.env.S3_SECRET_ACCESS_KEY.trim(),
      };
    }
    if (process.env.S3_VAULT_ACCESS_KEY_ID && process.env.S3_VAULT_SECRET_ACCESS_KEY) {
      this.vaultCreds = {
        accessKeyId: process.env.S3_VAULT_ACCESS_KEY_ID.trim(),
        secretAccessKey: process.env.S3_VAULT_SECRET_ACCESS_KEY.trim(),
      };
    }
  }

  private bumpApiCalls(count = 1) {
    const today = new Date().toISOString().slice(0, 10);
    if (today !== this.apiCallsDayKey) {
      this.apiCallsDayKey = today;
      this.apiCallsToday = 0;
    }
    this.apiCallsToday += count;
  }

  public getApiCallsToday(): number {
    const today = new Date().toISOString().slice(0, 10);
    if (today !== this.apiCallsDayKey) {
      this.apiCallsDayKey = today;
      this.apiCallsToday = 0;
    }
    return this.apiCallsToday;
  }

  public hasMonitorCreds(): boolean {
    return Boolean(this.monitorCreds?.accessKeyId && this.monitorCreds?.secretAccessKey);
  }

  public hasVaultCreds(): boolean {
    return Boolean(this.vaultCreds?.accessKeyId && this.vaultCreds?.secretAccessKey);
  }

  public setConfig(cfg: Partial<ExternalS3Config>) {
    this.config = { ...this.config, ...cfg };
  }

  public getConfig(): ExternalS3Config {
    return { ...this.config };
  }

  public setCredentials(params: {
    monitorAccessKeyId?: string;
    monitorSecretAccessKey?: string;
    vaultAccessKeyId?: string;
    vaultSecretAccessKey?: string;
    clearMonitor?: boolean;
    clearVault?: boolean;
  }) {
    if (params.clearMonitor) {
      this.monitorCreds = null;
    } else if (params.monitorAccessKeyId?.trim() && params.monitorSecretAccessKey?.trim()) {
      this.monitorCreds = {
        accessKeyId: params.monitorAccessKeyId.trim(),
        secretAccessKey: params.monitorSecretAccessKey.trim(),
      };
    }

    if (params.clearVault) {
      this.vaultCreds = null;
    } else if (params.vaultAccessKeyId?.trim() && params.vaultSecretAccessKey?.trim()) {
      this.vaultCreds = {
        accessKeyId: params.vaultAccessKeyId.trim(),
        secretAccessKey: params.vaultSecretAccessKey.trim(),
      };
    }
  }

  private buildClient(useVault = false): S3Client {
    const check = validateSafeExternalUrl(this.config.endpoint);
    if (!check.valid) {
      throw new Error(check.reason || 'External S3 endpoint URL rejected by safety policy.');
    }
    const creds = useVault ? (this.vaultCreds ?? this.monitorCreds) : this.monitorCreds;
    if (!creds) {
      throw new Error(
        useVault
          ? 'S3 vault credentials are not configured in server memory.'
          : 'S3 monitor credentials (Access Key ID & Secret Access Key) are required.',
      );
    }

    return new S3Client({
      region: this.config.region || 'us-east-1',
      endpoint: this.config.endpoint.replace(/\/+$/, ''),
      forcePathStyle: this.config.forcePathStyle,
      credentials: creds,
      maxAttempts: 2,
    });
  }

  public async verifyConnection(): Promise<ExternalBucketPosture> {
    const client = this.buildClient(false);
    const bucket = this.config.productionBucket.trim();
    if (!bucket) {
      throw new Error('Production bucket name is required.');
    }

    this.bumpApiCalls(1);
    await client.send(new HeadBucketCommand({ Bucket: bucket }));

    let versioningStatus: ExternalBucketPosture['versioningStatus'] = 'Unknown';
    try {
      this.bumpApiCalls(1);
      const ver = await client.send(new GetBucketVersioningCommand({ Bucket: bucket }));
      if (ver.Status === 'Enabled') versioningStatus = 'Enabled';
      else if (ver.Status === 'Suspended') versioningStatus = 'Suspended';
      else versioningStatus = 'Disabled';
    } catch {
      versioningStatus = 'Unknown';
    }

    let objectLockEnabled = false;
    try {
      this.bumpApiCalls(1);
      const lock = await client.send(new GetObjectLockConfigurationCommand({ Bucket: bucket }));
      objectLockEnabled = lock.ObjectLockConfiguration?.ObjectLockEnabled === 'Enabled';
    } catch {
      objectLockEnabled = false;
    }

    let vaultReachable = false;
    if (this.config.vaultBucket.trim()) {
      try {
        const vClient = this.buildClient(true);
        this.bumpApiCalls(1);
        await vClient.send(new HeadBucketCommand({ Bucket: this.config.vaultBucket.trim() }));
        vaultReachable = true;
      } catch {
        vaultReachable = false;
      }
    }

    return {
      reachable: true,
      versioningStatus,
      objectLockEnabled,
      vaultReachable,
      message: `Connected to ${this.config.provider} bucket "${bucket}" (versioning=${versioningStatus}, objectLock=${objectLockEnabled ? 'Enabled' : 'Off'}${vaultReachable ? `, vault="${this.config.vaultBucket}" verified` : ''}).`,
    };
  }

  public async listObjects(bucket: string, maxKeys = 150): Promise<ExternalObjectItem[]> {
    const client = this.buildClient(false);
    this.bumpApiCalls(1);
    const res = await client.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        MaxKeys: Math.min(250, maxKeys),
      }),
    );

    const items: ExternalObjectItem[] = [];
    for (const obj of res.Contents ?? []) {
      if (!obj.Key) continue;
      items.push({
        key: obj.Key,
        sizeBytes: obj.Size ?? 0,
        etag: (obj.ETag ?? '').replace(/"/g, ''),
        lastModified: (obj.LastModified ?? new Date()).toISOString(),
      });
    }
    return items;
  }

  /**
   * Fetches ONLY the first 64 KB via S3 Range header so entropy & magic-byte inspection
   * stays sub-second and minimizes free-tier egress bandwidth.
   */
  public async readObjectRange64KB(bucket: string, key: string): Promise<ExternalRangeInspection> {
    const client = this.buildClient(false);
    this.bumpApiCalls(1);
    const res = await client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        Range: 'bytes=0-65535',
      }),
    );
    const buf = await streamToBuffer(res.Body, 65536);
    const entropy = computeShannonEntropy(buf, 65536);
    const magic = inspectMagicHeader(buf, key);
    return {
      buffer: buf,
      entropy,
      magicValid: magic.valid,
      magicDetected: magic.detectedType,
      sha256Prefix: sha256Hex(buf),
      contentLength: res.ContentLength ?? buf.length,
    };
  }

  public async getObjectFull(
    bucket: string,
    key: string,
    useVault = false,
  ): Promise<{ buffer: Buffer; contentType: string; sha256: string }> {
    const client = this.buildClient(useVault);
    this.bumpApiCalls(1);
    const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    const buffer = await streamToBuffer(res.Body, 10 * 1024 * 1024);
    return {
      buffer,
      contentType: res.ContentType || 'application/octet-stream',
      sha256: sha256Hex(buffer),
    };
  }

  public async putObject(params: {
    bucket: string;
    key: string;
    buffer: Buffer;
    contentType?: string;
    useVault?: boolean;
  }): Promise<{ etag?: string; versionId?: string }> {
    const client = this.buildClient(Boolean(params.useVault));
    this.bumpApiCalls(1);
    const res = await client.send(
      new PutObjectCommand({
        Bucket: params.bucket,
        Key: params.key,
        Body: params.buffer,
        ContentType: params.contentType || 'application/octet-stream',
      }),
    );
    return {
      etag: res.ETag?.replace(/"/g, ''),
      versionId: res.VersionId,
    };
  }

  public async deleteObject(bucket: string, key: string): Promise<void> {
    const client = this.buildClient(false);
    this.bumpApiCalls(1);
    await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
  }

  /**
   * Quota-safe ETag change poller:
   * - First run establishes the baseline snapshot without false alarms.
   * - Subsequent runs only issue 64 KB Range reads for objects whose ETag changed or are newly added.
   */
  public async pollBucketChanges(bucket: string): Promise<{ diffs: PollDiffItem[]; totalObjects: number }> {
    const objects = await this.listObjects(bucket, 150);
    const seenKeys = new Set<string>();
    const diffs: PollDiffItem[] = [];
    const hasPriorBaseline = Array.from(this.etagCache.keys()).some((k) => k.startsWith(`${bucket}/`));

    for (const obj of objects) {
      const cacheKey = `${bucket}/${obj.key}`;
      seenKeys.add(cacheKey);
      const prev = this.etagCache.get(cacheKey);

      if (!hasPriorBaseline) {
        this.etagCache.set(cacheKey, {
          etag: obj.etag,
          size: obj.sizeBytes,
          entropy: 4.5,
          seeded: true,
        });
        continue;
      }

      if (!prev) {
        let inspection: ExternalRangeInspection | undefined;
        try {
          inspection = await this.readObjectRange64KB(bucket, obj.key);
        } catch {
          // Ignore transient read error on deleted key
        }
        this.etagCache.set(cacheKey, {
          etag: obj.etag,
          size: obj.sizeBytes,
          entropy: inspection?.entropy ?? 4.5,
          seeded: true,
        });
        diffs.push({
          bucket,
          key: obj.key,
          kind: 'created',
          etag: obj.etag,
          sizeBytes: obj.sizeBytes,
          inspection,
        });
      } else if (prev.etag !== obj.etag || prev.size !== obj.sizeBytes) {
        let inspection: ExternalRangeInspection | undefined;
        try {
          inspection = await this.readObjectRange64KB(bucket, obj.key);
        } catch {
          // Ignore transient read error
        }
        const prevEntropy = prev.entropy;
        this.etagCache.set(cacheKey, {
          etag: obj.etag,
          size: obj.sizeBytes,
          entropy: inspection?.entropy ?? prev.entropy,
          seeded: true,
        });
        diffs.push({
          bucket,
          key: obj.key,
          kind: 'modified',
          etag: obj.etag,
          sizeBytes: obj.sizeBytes,
          prevEntropy,
          inspection,
        });
      }
    }

    if (hasPriorBaseline) {
      for (const cachedKey of Array.from(this.etagCache.keys())) {
        if (cachedKey.startsWith(`${bucket}/`) && !seenKeys.has(cachedKey)) {
          const objKey = cachedKey.slice(bucket.length + 1);
          this.etagCache.delete(cachedKey);
          diffs.push({
            bucket,
            key: objKey,
            kind: 'deleted',
            etag: '',
            sizeBytes: 0,
          });
        }
      }
    }

    return { diffs, totalObjects: objects.length };
  }

  public resetPollBaseline() {
    this.etagCache.clear();
  }
}
