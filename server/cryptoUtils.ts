import crypto from 'crypto';

export interface MagicCheckResult {
  valid: boolean;
  detectedType: string;
}

/**
 * Computes Shannon entropy H = -sum(p_i * log2(p_i)) over the first sampleBytes (default 64 KB).
 */
export function computeShannonEntropy(buffer: Buffer, sampleBytes = 65536): number {
  const len = Math.min(buffer.length, sampleBytes);
  if (len === 0) return 0;

  const counts = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    counts[buffer[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === 0) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function sha256Hex(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Validates file magic bytes against known document/image headers (%PDF, PK\x03\x04, JPEG, PNG)
 * or printable UTF-8 text (CSV, TXT, JSON).
 */
export function inspectMagicHeader(buffer: Buffer, key?: string): MagicCheckResult {
  if (buffer.length < 4) {
    return { valid: false, detectedType: 'UNKNOWN_SHORT' };
  }

  // %PDF (25 50 44 46)
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    return { valid: true, detectedType: 'PDF' };
  }
  // PK\x03\x04 (ZIP / DOCX / XLSX)
  if (buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return { valid: true, detectedType: 'OOXML/ZIP' };
  }
  // JPEG (FF D8 FF)
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { valid: true, detectedType: 'JPEG' };
  }
  // PNG (89 50 4E 47)
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return { valid: true, detectedType: 'PNG' };
  }

  // Check if extension expects plain text (.csv, .txt, .json, .md) and bytes are printable ASCII/UTF-8
  const ext = key ? key.toLowerCase().split('.').pop() : '';
  const sampleLen = Math.min(buffer.length, 512);
  let printable = 0;
  for (let i = 0; i < sampleLen; i++) {
    const b = buffer[i];
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) {
      printable++;
    }
  }
  if (printable / sampleLen > 0.92) {
    const label = ext === 'csv' ? 'CSV' : ext === 'json' ? 'JSON' : 'TEXT';
    return { valid: true, detectedType: label };
  }

  return { valid: false, detectedType: 'RAW/ENCRYPTED' };
}

/**
 * Encrypts a buffer using real AES-256-GCM, destroying its original magic header and raising entropy to ~7.98.
 */
export function encryptBufferAes256(plain: Buffer): Buffer {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Prepend IV + tag + ciphertext (no valid document magic header)
  return Buffer.concat([iv, tag, encrypted]);
}

/**
 * Generates realistic binary file buffers with authentic magic headers and realistic entropy profiles.
 */
export function generateRealisticFileBuffer(
  fileType: 'pdf' | 'docx' | 'xlsx' | 'jpg' | 'png' | 'csv' | 'txt',
  bodyText: string,
  targetBytes = 12288,
): Buffer {
  const repeatedText = buildStructuredText(bodyText, Math.max(2048, targetBytes));

  if (fileType === 'pdf') {
    const header = Buffer.from(
      `%PDF-1.7\n%DefySwarm Synthetic Business Document\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n4 0 obj << /Length ${repeatedText.length} >> stream\n`,
      'utf8',
    );
    const footer = Buffer.from('\nendstream\nendobj\n%%EOF\n', 'utf8');
    return Buffer.concat([header, Buffer.from(repeatedText, 'utf8'), footer]);
  }

  if (fileType === 'docx' || fileType === 'xlsx') {
    // Authentic ZIP local file header (PK\x03\x04) + realistic compressed-like payload + readable metadata tail
    const pkHeader = Buffer.from([
      0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00,
    ]);
    const xmlTag = Buffer.from(
      fileType === 'xlsx' ? 'xl/worksheets/sheet1.xml' : 'word/document.xml',
      'utf8',
    );
    // Mix moderate-entropy pseudo-compressed stream with structured text so valid OOXML header passes
    const compressedChunk = crypto.randomBytes(Math.min(4096, Math.floor(targetBytes * 0.45)));
    const textChunk = Buffer.from(repeatedText.slice(0, Math.floor(targetBytes * 0.55)), 'utf8');
    return Buffer.concat([pkHeader, xmlTag, textChunk, compressedChunk]);
  }

  if (fileType === 'jpg') {
    // Valid JPEG SOI + APP0 JFIF header + high-entropy image payload + EOI
    const jpgHeader = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00,
      0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    const comment = Buffer.from(bodyText.slice(0, 180), 'utf8');
    const payload = crypto.randomBytes(Math.max(4096, targetBytes - 64));
    const eoi = Buffer.from([0xff, 0xd9]);
    return Buffer.concat([jpgHeader, comment, payload, eoi]);
  }

  if (fileType === 'png') {
    // Valid PNG signature + IHDR marker + high-entropy compressed image scanlines
    const pngHeader = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
      0x52,
    ]);
    const payload = crypto.randomBytes(Math.max(4096, targetBytes - 32));
    return Buffer.concat([pngHeader, payload]);
  }

  // CSV or TXT
  return Buffer.from(repeatedText, 'utf8');
}

function buildStructuredText(seed: string, minLength: number): string {
  const lines = [
    seed,
    'period,cost_center,account_code,variance_usd,reviewer_status',
    '2026-Q3,CC-4102,GL-5100,14820.50,reconciled',
    '2026-Q3,CC-4108,GL-5210,-3240.00,approved',
    '2026-Q3,CC-4215,GL-6040,48910.25,reconciled',
    '2026-Q3,CC-4301,GL-6180,9125.00,pending_audit',
  ];
  let out = lines.join('\n') + '\n';
  let idx = 1;
  while (out.length < minLength) {
    out += `2026-Q3,CC-${4100 + (idx % 90)},GL-${5100 + (idx % 40)},${(
      1250 +
      ((idx * 379) % 18000)
    ).toFixed(2)},reconciled\n`;
    idx++;
  }
  return out;
}

export function inferFileTypeFromKey(
  key: string,
): 'pdf' | 'docx' | 'xlsx' | 'jpg' | 'png' | 'csv' | 'txt' {
  const lower = key.toLowerCase();
  if (lower.endsWith('.pdf')) return 'pdf';
  if (lower.endsWith('.docx')) return 'docx';
  if (lower.endsWith('.xlsx')) return 'xlsx';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'jpg';
  if (lower.endsWith('.png')) return 'png';
  if (lower.endsWith('.csv')) return 'csv';
  return 'txt';
}
