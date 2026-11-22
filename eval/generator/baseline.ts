import type { Event } from '../types.ts';

export type FileType = 'pdf' | 'docx' | 'xlsx' | 'csv' | 'txt' | 'png' | 'jpg' | 'zip' | 'gz' | 'log';

export interface BaselineFile {
  key: string;
  type: FileType;
  entropy: number;
  sizeBytes: number;
}

export const BUCKET = 'finance-prod';

export const ALLOWLISTED_PRINCIPALS = ['ci-deployer', 'backup-agent', 'dlp-scanner'];

export const BENIGN_PRINCIPALS = [
  'ci-deployer',
  'backup-agent',
  'dlp-scanner',
  'dev-workstation',
  'photo-sync',
  'app-log-writer',
  'analyst-jdoe',
  'finance-user',
];

export const ATTACKER_POOL = [
  'svc-billing-etl',
  'swarm-node-alpha',
  'swarm-node-beta',
  'swarm-node-gamma',
  'swarm-node-delta',
  'swarm-node-epsilon',
  'swarm-node-zeta',
  'swarm-node-eta',
  'swarm-node-theta',
];

const BASE_ENTROPY: Record<FileType, number> = {
  pdf: 5.2,
  docx: 5.6,
  xlsx: 5.4,
  csv: 4.8,
  txt: 4.5,
  png: 7.4,
  jpg: 7.3,
  zip: 7.6,
  gz: 7.7,
  log: 4.9,
};

const BASE_SIZE: Record<FileType, number> = {
  pdf: 420_000,
  docx: 180_000,
  xlsx: 240_000,
  csv: 90_000,
  txt: 24_000,
  png: 1_800_000,
  jpg: 2_400_000,
  zip: 6_500_000,
  gz: 1_100_000,
  log: 48_000,
};

export const BASELINE_FILES: BaselineFile[] = [
  ['finance/2026/Q3/consolidated_balance_sheet.pdf', 'pdf'],
  ['finance/2026/Q3/payroll_register_october.csv', 'csv'],
  ['finance/2026/Q3/vendor_settlement_batch_14.xlsx', 'xlsx'],
  ['finance/2026/Q3/board_audit_briefing.docx', 'docx'],
  ['finance/2026/Q2/revenue_recognition_asc606.pdf', 'pdf'],
  ['finance/2026/Q2/tax_provision_workpaper.xlsx', 'xlsx'],
  ['finance/2026/Q2/treasury_fx_hedging_policy.docx', 'docx'],
  ['finance/2026/Q1/external_audit_signoff.pdf', 'pdf'],
  ['finance/2026/Q1/gl_trial_balance_march.csv', 'csv'],
  ['finance/2026/ap/northwind_logistics_inv_8841.pdf', 'pdf'],
  ['finance/2026/ap/cloud_infra_commit_q3.csv', 'csv'],
  ['finance/2026/ap/meridian_advisory_retainer.pdf', 'pdf'],
  ['finance/2026/ar/enterprise_renewals_pipeline.xlsx', 'xlsx'],
  ['finance/2026/ar/customer_collections_log.csv', 'csv'],
  ['operations/2026/datacenter_power_telemetry.csv', 'csv'],
  ['operations/2026/dr_failover_runbook_v4.docx', 'docx'],
  ['operations/2026/hardware_asset_register.xlsx', 'xlsx'],
  ['operations/2026/site_floorplan_west_wing.png', 'png'],
  ['operations/2026/facility_badge_photo_ref.jpg', 'jpg'],
  ['hr/2026/benefits_enrollment_guide.pdf', 'pdf'],
  ['hr/2026/compensation_bands_fy26.xlsx', 'xlsx'],
  ['hr/2026/onboarding_handbook_rev9.docx', 'docx'],
  ['legal/2026/msa_template_enterprise_v7.docx', 'docx'],
  ['legal/2026/dpa_eu_standard_clauses.pdf', 'pdf'],
  ['legal/2026/cyber_insurance_binder_2026.pdf', 'pdf'],
  ['product/2026/q4_roadmap_priorities.docx', 'docx'],
  ['product/2026/customer_nps_synthesis.csv', 'csv'],
  ['product/2026/architecture_diagram_v3.png', 'png'],
  ['finance/2026/Q3/intercompany_eliminations.csv', 'csv'],
  ['finance/2026/Q3/capex_depreciation_schedule.xlsx', 'xlsx'],
  ['finance/2026/Q3/quarterly_cashflow_forecast.pdf', 'pdf'],
  ['finance/2026/Q3/procurement_approval_matrix.docx', 'docx'],
  ['finance/2026/Q3/travel_expense_summary.csv', 'csv'],
  ['finance/2026/Q3/equity_grant_vesting_log.csv', 'csv'],
  ['finance/2026/Q3/bank_reconciliation_chase.pdf', 'pdf'],
  ['finance/2026/Q3/margin_analysis_by_region.xlsx', 'xlsx'],
  ['operations/2026/soc2_control_evidence.pdf', 'pdf'],
  ['legal/2026/vendor_dpa_register.xlsx', 'xlsx'],
  ['hr/2026/performance_review_cycle.docx', 'docx'],
  ['product/2026/release_notes_2026_10.md.txt', 'txt'],
].map(([key, type]) => ({
  key: key as string,
  type: type as FileType,
  entropy: BASE_ENTROPY[type as FileType],
  sizeBytes: BASE_SIZE[type as FileType],
}));

export const ADAPTIVE_CANARY_KEYS = [
  'finance/2026/Q3/vendor_reconciliation_ledger.xlsx',
  'finance/2026/Q3/treasury_sweep_confirmation.pdf',
  'finance/2026/ap/atlas_freight_statement_sept.pdf',
  'finance/2026/ar/q3_deferred_billing_schedule.csv',
  'finance/2026/Q2/fixed_asset_rollforward.xlsx',
  'operations/2026/vendor_sla_quarterly_review.docx',
  'legal/2026/subprocessor_registry_q3.pdf',
  'hr/2026/regional_holiday_calendar_fy26.docx',
  'finance/2026/Q3/cost_allocation_shared_it.csv',
  'finance/2026/Q1/audit_sampling_request_list.docx',
];

export const OBVIOUS_CANARY_KEYS = [
  '_DO_NOT_DELETE_CANARY.txt',
  'zzz_canary_do_not_touch.docx',
  'CANARY_TRIPWIRE.xlsx',
];

export function typeFromKey(key: string): FileType {
  const lower = key.toLowerCase();
  if (lower.endsWith('.pdf')) return 'pdf';
  if (lower.endsWith('.docx')) return 'docx';
  if (lower.endsWith('.xlsx')) return 'xlsx';
  if (lower.endsWith('.csv')) return 'csv';
  if (lower.endsWith('.png')) return 'png';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'jpg';
  if (lower.endsWith('.zip')) return 'zip';
  if (lower.endsWith('.gz') || lower.endsWith('.log.gz')) return 'gz';
  if (lower.endsWith('.txt') || lower.endsWith('.md.txt')) return 'txt';
  return 'log';
}

export function baseEntropyFor(key: string): number {
  return BASE_ENTROPY[typeFromKey(key)];
}

export function baseSizeFor(key: string): number {
  return BASE_SIZE[typeFromKey(key)];
}

export function magicFor(type: FileType): string {
  switch (type) {
    case 'pdf':
      return 'PDF';
    case 'docx':
      return 'ZIP/OOXML';
    case 'xlsx':
      return 'ZIP/OOXML';
    case 'zip':
      return 'ZIP';
    case 'gz':
      return 'GZIP';
    case 'png':
      return 'PNG';
    case 'jpg':
      return 'JPEG';
    case 'csv':
      return 'TEXT/CSV';
    case 'txt':
      return 'TEXT';
    default:
      return 'TEXT';
  }
}

export function makeEvent(
  seq: number,
  timeMs: number,
  partial: Omit<Event, 'seq' | 'timeMs' | 'bucket' | 'plane' | 'channel' | 'httpStatus'> & {
    channel?: Event['channel'];
    httpStatus?: number;
    plane?: Event['plane'];
    bucket?: string;
  },
): Event {
  return {
    seq,
    timeMs,
    bucket: partial.bucket ?? BUCKET,
    plane: partial.plane ?? (partial.operation.startsWith('PutBucket') || partial.operation.startsWith('DeleteObjectVersion') || partial.operation === 'PutObjectLockConfiguration' || partial.operation === 'PutBucketLogging' ? 'control' : 'data'),
    channel: partial.channel ?? 'api',
    httpStatus: partial.httpStatus ?? 200,
    ...partial,
  };
}
