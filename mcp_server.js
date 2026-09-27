'use strict';

/**
 * BobSpec-Provenance MCP Server
 *
 * Unified MCP server combining:
 *   - Provenance tamper-evident SHA-256 hash-chained audit ledger
 *   - BobSpec compliance classification and risk mapping
 *
 * Reads and writes the SAME ledger.jsonl that the Python BobSpec
 * orchestrator writes to, giving MCP clients a live view of every
 * audit action taken by the Python side.
 *
 * Tools:
 *   log_action           — append a tamper-evident entry + compliance classification
 *   verify_ledger        — recompute every hash and prevHash link
 *   get_ledger           — return all entries, optionally filtered by minRisk
 *   generate_audit_report — full Markdown report with integrity status + full log
 *   get_compliance_summary — aggregate compliance stats across the ledger
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

// ── Ledger path — shared with the Python BobSpec orchestrator ─────────────────
const LEDGER_PATH = process.env.PROVENANCE_LEDGER_PATH ||
  path.join(__dirname, 'data', 'ledger.jsonl');

// ── Compliance classification rules ──────────────────────────────────────────
const RISK_ORDER = ['low', 'medium', 'high'];

const COMPLIANCE_RULES = [
  { keywords: ['auth', 'login', 'token', 'oauth'],           frameworks: ['SOC2 CC6.1', 'FedRAMP AC-2'],            risk: 'high'   },
  { keywords: ['patient', 'phi', 'health', 'hipaa'],         frameworks: ['HIPAA §164.312'],                        risk: 'high'   },
  { keywords: ['payment', 'card', 'pci', 'billing'],         frameworks: ['PCI DSS 6.2'],                           risk: 'high'   },
  { keywords: ['pii', 'personal data', 'email', 'ssn'],      frameworks: ['GDPR Art.32'],                           risk: 'high'   },
  { keywords: ['patch_applied', 'patch_verification'],        frameworks: ['PCI DSS 6.2', 'SOC2 CC6.1'],            risk: 'high'   },
  { keywords: ['audit_started', 'audit_complete'],            frameworks: ['SOC2 CC6.1', 'FedRAMP AC-2'],            risk: 'high'   },
  { keywords: ['subagent_audit', 'orchestrat'],               frameworks: ['EU AI Act Art.12', 'EU AI Act Art.14'],  risk: 'medium' },
  { keywords: ['model', 'prompt', 'inference', 'agent'],      frameworks: ['EU AI Act Art.12', 'EU AI Act Art.14'],  risk: 'medium' },
  { keywords: ['report_generated', 'advisory_query'],         frameworks: ['EU AI Act Art.12'],                      risk: 'medium' },
  { keywords: ['spec', 'spec_loaded', 'plan_generated'],      frameworks: ['SOC2 CC6.1'],                            risk: 'medium' },
  { keywords: ['test', 'spec', 'readme', 'doc'],              frameworks: [],                                        risk: 'low'    },
];

/**
 * Classify a ledger entry against the compliance rule set.
 * @param {{ description: string, actionType?: string, filesChanged?: string[] }} entry
 * @returns {{ frameworks: string[], risk: 'low'|'medium'|'high' }}
 */
function classify(entry) {
  const haystack = [
    entry.description || '',
    entry.actionType || '',
    ...(entry.filesChanged || []),
  ].join(' ').toLowerCase();

  const matchedFrameworks = new Set();
  let maxRiskIdx = 0;

  for (const rule of COMPLIANCE_RULES) {
    if (rule.keywords.some((kw) => haystack.includes(kw))) {
      rule.frameworks.forEach((f) => matchedFrameworks.add(f));
      const rIdx = RISK_ORDER.indexOf(rule.risk);
      if (rIdx > maxRiskIdx) maxRiskIdx = rIdx;
    }
  }

  return {
    frameworks: Array.from(matchedFrameworks),
    risk: RISK_ORDER[maxRiskIdx],
  };
}

// ── Pure ledger operations (stateless, read from disk each call) ──────────────
const ZERO_HASH = '0'.repeat(64);

function readEntries() {
  if (!fs.existsSync(LEDGER_PATH)) return [];
  const raw = fs.readFileSync(LEDGER_PATH, 'utf8').trim();
  if (!raw) return [];
  return raw.split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

function computeHash(entry) {
  const { hash: _omit, ...payload } = entry;
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

function appendEntry(action) {
  // Ensure directory exists
  const dir = path.dirname(LEDGER_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const entries = readEntries();
  const prevEntry = entries.length > 0 ? entries[entries.length - 1] : null;
  const prevHash = prevEntry ? prevEntry.hash : ZERO_HASH;
  const seq = entries.length + 1;

  const entry = {
    seq,
    timestamp: new Date().toISOString(),
    actor: action.actor,
    actionType: action.actionType,
    description: action.description,
    filesChanged: action.filesChanged || [],
    mode: action.mode || null,
    humanApproved: action.humanApproved !== undefined ? action.humanApproved : null,
    prevHash,
    hash: null,
  };
  entry.hash = computeHash(entry);

  fs.appendFileSync(LEDGER_PATH, JSON.stringify(entry) + '\n', 'utf8');
  return entry;
}

function verifyChain() {
  const entries = readEntries();
  const breaks = [];
  let expectedPrevHash = ZERO_HASH;

  for (const entry of entries) {
    if (entry.prevHash !== expectedPrevHash) {
      breaks.push({ seq: entry.seq, reason: `prevHash mismatch (expected ${expectedPrevHash.slice(0, 8)}…, got ${entry.prevHash.slice(0, 8)}…)` });
    }
    const recomputed = computeHash(entry);
    if (recomputed !== entry.hash) {
      breaks.push({ seq: entry.seq, reason: 'hash mismatch — entry has been tampered with' });
    }
    expectedPrevHash = entry.hash;
  }

  return { valid: breaks.length === 0, entryCount: entries.length, breaks };
}

// ── MCP Server setup ──────────────────────────────────────────────────────────
const server = new McpServer({ name: 'bobspec-provenance', version: '1.0.0' });

// ── Tool 1: log_action ────────────────────────────────────────────────────────
server.registerTool(
  'log_action',
  {
    description: 'Append a tamper-evident entry to the BobSpec-Provenance audit ledger. Returns the entry metadata and its compliance classification.',
    inputSchema: z.object({
      actor: z.string().describe('Who or what performed the action (user, agent id, service name)'),
      actionType: z.string().describe('Short action category, e.g. code_change, config_update, patch_applied, audit_started'),
      description: z.string().describe('Human-readable description of what was done'),
      filesChanged: z.array(z.string()).optional().describe('List of file paths affected'),
      mode: z.string().optional().describe('Execution mode: agent, manual, ci, plan'),
      humanApproved: z.boolean().optional().describe('Whether a human explicitly approved this action'),
    }),
  },
  async ({ actor, actionType, description, filesChanged, mode, humanApproved }) => {
    const entry = appendEntry({ actor, actionType, description, filesChanged, mode, humanApproved });
    const { frameworks, risk } = classify(entry);
    const result = {
      logged: { seq: entry.seq, timestamp: entry.timestamp, hash: entry.hash },
      complianceFrameworks: frameworks,
      riskLevel: risk,
    };
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Tool 2: verify_ledger ─────────────────────────────────────────────────────
server.registerTool(
  'verify_ledger',
  {
    description: 'Verify the integrity of the entire BobSpec-Provenance audit ledger by recomputing and checking each SHA-256 hash and prevHash link. Detects any post-hoc tampering.',
    inputSchema: z.object({}),
  },
  async () => {
    const result = verifyChain();
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }
);

// ── Tool 3: get_ledger ────────────────────────────────────────────────────────
server.registerTool(
  'get_ledger',
  {
    description: 'Return ledger entries including BobSpec audit events, optionally filtered to a minimum risk level.',
    inputSchema: z.object({
      minRisk: z.enum(['low', 'medium', 'high']).optional()
        .describe('Minimum risk level to include. Omit to return all entries.'),
    }),
  },
  async ({ minRisk }) => {
    const entries = readEntries();
    const minIdx = minRisk ? RISK_ORDER.indexOf(minRisk) : 0;
    const filtered = entries.filter((e) => {
      const { risk } = classify(e);
      return RISK_ORDER.indexOf(risk) >= minIdx;
    });
    return { content: [{ type: 'text', text: JSON.stringify(filtered, null, 2) }] };
  }
);

// ── Tool 4: generate_audit_report ─────────────────────────────────────────────
server.registerTool(
  'generate_audit_report',
  {
    description: 'Generate a full Markdown audit report with integrity status, high-risk entries table, BobSpec audit events, and full provenance log.',
    inputSchema: z.object({}),
  },
  async () => {
    const entries = readEntries();
    const chain = verifyChain();

    const integrityBadge = chain.valid ? '✅ VALID' : '❌ COMPROMISED';
    const breakLines = chain.breaks.length > 0
      ? chain.breaks.map((b) => `- Seq \`${b.seq}\`: ${b.reason}`).join('\n')
      : '_None_';

    const highRisk = entries.filter((e) => classify(e).risk === 'high');
    const highRiskRows = highRisk.length > 0
      ? highRisk.map((e) => {
          const { frameworks } = classify(e);
          const approved = e.humanApproved === true ? 'Yes' : e.humanApproved === false ? 'No' : '—';
          return `| ${e.seq} | ${e.timestamp.slice(0, 19)} | ${e.actor} | ${(e.description || '').replace(/\|/g, '\\|').slice(0, 80)} | ${frameworks.join(', ') || '—'} | ${approved} |`;
        }).join('\n')
      : '| — | — | — | _No high-risk entries_ | — | — |';

    // Separate BobSpec system events from user-originated events
    const bobspecEvents = entries.filter((e) =>
      ['audit_started', 'audit_complete', 'subagent_audit_complete', 'patch_applied',
       'patch_verification', 'plan_generated', 'report_generated', 'spec_loaded'].includes(e.actionType)
    );
    const bobspecRows = bobspecEvents.length > 0
      ? bobspecEvents.map((e) =>
          `| ${e.seq} | ${e.timestamp.slice(0, 19)} | ${e.actor} | ${e.actionType} | ${(e.description || '').slice(0, 80)} |`
        ).join('\n')
      : '| — | — | — | — | _No BobSpec events_ |';

    const allRows = entries.length > 0
      ? entries.map((e) => {
          const { risk, frameworks } = classify(e);
          const approved = e.humanApproved === true ? 'Yes' : e.humanApproved === false ? 'No' : '—';
          return `| ${e.seq} | ${e.timestamp.slice(0, 19)} | ${e.actor} | ${e.actionType} | ${(e.description || '').replace(/\|/g, '\\|').slice(0, 60)} | ${risk} | ${frameworks.join(', ') || '—'} | ${approved} |`;
        }).join('\n')
      : '| — | — | — | — | _No entries_ | — | — | — |';

    const report = `# BobSpec-Provenance Audit Report

Generated: ${new Date().toISOString()}

## Integrity Status

**Chain integrity:** ${integrityBadge}
**Total entries:** ${chain.entryCount}
**Compliance frameworks covered:** EU AI Act Art.12/14, HIPAA §164.312, FedRAMP AC-2, SOC2 CC6.1, PCI DSS, GDPR Art.32

### Integrity breaks
${breakLines}

---

## High-Risk Entries

| Seq | Timestamp | Actor | Description | Frameworks | Human Approved |
|-----|-----------|-------|-------------|------------|----------------|
${highRiskRows}

---

## BobSpec Orchestration Events

| Seq | Timestamp | Actor | Action Type | Description |
|-----|-----------|-------|-------------|-------------|
${bobspecRows}

---

## Full Provenance Log

| Seq | Timestamp | Actor | Action Type | Description | Risk | Frameworks | Human Approved |
|-----|-----------|-------|-------------|-------------|------|------------|----------------|
${allRows}
`;

    return { content: [{ type: 'text', text: report }] };
  }
);

// ── Tool 5: get_compliance_summary ────────────────────────────────────────────
server.registerTool(
  'get_compliance_summary',
  {
    description: 'Return aggregate compliance statistics across the entire provenance ledger: risk distribution, framework coverage, BobSpec audit event counts.',
    inputSchema: z.object({}),
  },
  async () => {
    const entries = readEntries();
    const chain = verifyChain();

    const riskCounts = { low: 0, medium: 0, high: 0 };
    const frameworkCounts = {};
    const actionTypeCounts = {};

    for (const entry of entries) {
      const { risk, frameworks } = classify(entry);
      riskCounts[risk] = (riskCounts[risk] || 0) + 1;
      frameworks.forEach((f) => { frameworkCounts[f] = (frameworkCounts[f] || 0) + 1; });
      const at = entry.actionType || 'unknown';
      actionTypeCounts[at] = (actionTypeCounts[at] || 0) + 1;
    }

    const patchEvents = entries.filter((e) => e.actionType === 'patch_applied');
    const auditRuns = entries.filter((e) => e.actionType === 'audit_complete');
    const lastAudit = auditRuns.length > 0 ? auditRuns[auditRuns.length - 1] : null;

    const summary = {
      ledger: {
        entryCount: chain.entryCount,
        chainValid: chain.valid,
        breaks: chain.breaks.length,
      },
      riskDistribution: riskCounts,
      frameworkCoverage: frameworkCounts,
      actionTypeCounts,
      bobspec: {
        auditRunsTotal: auditRuns.length,
        patchesApplied: patchEvents.length,
        lastAuditTimestamp: lastAudit ? lastAudit.timestamp : null,
        lastAuditDescription: lastAudit ? lastAudit.description : null,
      },
    };

    return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
  }
);

// ── Start server ──────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`BobSpec-Provenance MCP server running on stdio — ledger: ${LEDGER_PATH}`);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
