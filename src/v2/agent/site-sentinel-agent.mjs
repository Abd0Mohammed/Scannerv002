#!/usr/bin/env node
/**
 * Site Sentinel V2 — Least-Privilege Read-Only Inspection Agent
 *
 * Security guarantees:
 * - Read-only inspection only; never executes remote commands or modifies files.
 * - Authenticates exclusively via user-supplied revocable Bearer token.
 * - Only inspects explicit --target-dir configuration permissions and runtime posture.
 * - Reports exact inspected checks (passed, failed, skipped) so incomplete coverage never inflates scores.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const serverUrl = (process.env.SENTINEL_SERVER || 'http://localhost:3000').replace(/\/+$/, '');
const targetDirIdx = process.argv.indexOf('--target-dir');
const targetDir = targetDirIdx !== -1 && process.argv[targetDirIdx + 1] ? path.resolve(process.argv[targetDirIdx + 1]) : process.cwd();

function getAuthHeaders() {
  const token = process.env.SENTINEL_TOKEN || '';
  if (!token || !token.startsWith('ss_agent_')) {
    console.error('Error: SENTINEL_TOKEN environment variable must be set to a valid ss_agent_... token.');
    process.exit(1);
  }
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };
}

function sanitizeText(text) {
  return String(text || '')
    .replace(/ss_agent_[a-zA-Z0-9]+/g, 'ss_agent_****')
    .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA****');
}

async function sendHeartbeat(headers) {
  const res = await fetch(`${serverUrl}/api/v2/agent/heartbeat`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      hostname: os.hostname(),
      osInfo: `${os.type()} ${os.release()} (${os.arch()})`,
      agentVersion: '2.1.0-readonly'
    })
  });
  if (!res.ok) {
    throw new Error(`Heartbeat rejected (${res.status}): ${await res.text()}`);
  }
  return res.json();
}

export function inspectReadOnlyPosture(dir) {
  const findings = [];
  const inspectedChecks = [];
  let checkedPaths = 0;
  const nowIso = new Date().toISOString();

  // 1. Check process UID (Unix/Linux/macOS only)
  if (typeof process.getuid === 'function') {
    const uid = process.getuid();
    if (uid === 0) {
      inspectedChecks.push({
        id: 'agent_runtime_uid',
        name: 'Non-Root Process Execution Check',
        status: 'failed',
        detail: 'process.getuid() returned 0 (root)'
      });
      findings.push({
        checkId: 'agent_runtime_uid',
        title: 'Inspection Agent or Service Executed as Root User (UID 0)',
        severity: 'medium',
        category: 'Code & Secrets',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'POSIX Process UID Syscall Inspection',
        affectedResource: `${os.hostname()} (UID 0)`,
        observedAt: nowIso,
        description: 'Process is running with root UID 0 privileges.',
        impact: 'Violates least-privilege isolation if application runtime shares the same UID.',
        remediation: 'Run Site Sentinel Agent and web application services under dedicated non-root system accounts.',
        evidence: { detail: 'process.getuid() === 0' },
        cwe: 'CWE-250'
      });
    } else {
      inspectedChecks.push({
        id: 'agent_runtime_uid',
        name: 'Non-Root Process Execution Check',
        status: 'passed',
        detail: `Running as non-root UID ${uid}`
      });
    }
  } else {
    inspectedChecks.push({
      id: 'agent_runtime_uid',
      name: 'Non-Root Process Execution Check',
      status: 'skipped',
      detail: 'POSIX getuid() unavailable on this operating system'
    });
  }

  // 2. Verify target directory exists
  if (!fs.existsSync(dir)) {
    inspectedChecks.push({
      id: 'agent_target_dir',
      name: 'Target Directory Accessibility',
      status: 'skipped',
      detail: `Target directory "${dir}" does not exist`
    });
    return { findings, checkedPaths, inspectedChecks };
  }

  const sensitiveConfigFiles = ['.env', '.env.production', 'wp-config.php', 'config.php', 'settings.py', 'appsettings.json'];
  let existingConfigFiles = 0;

  for (const fname of sensitiveConfigFiles) {
    const fullPath = path.join(dir, fname);
    checkedPaths++;
    if (!fs.existsSync(fullPath)) continue;
    existingConfigFiles++;

    try {
      const stat = fs.statSync(fullPath);
      const mode = stat.mode & 0o777;
      if ((mode & 0o004) !== 0 || (mode & 0o002) !== 0) {
        inspectedChecks.push({
          id: `agent_perm_${fname}`,
          name: `File Permissions on ${fname}`,
          status: 'failed',
          detail: `Mode 0${mode.toString(8)} allows world read/write`
        });
        findings.push({
          checkId: `agent_perm_${fname}`,
          title: `Overly Permissive File Permissions on ${fname} (${mode.toString(8)})`,
          severity: (mode & 0o002) !== 0 ? 'critical' : 'high',
          category: 'Code & Secrets',
          confidence: 'confirmed',
          accuracyTier: 'VERIFIED',
          detectionMethod: 'Filesystem stat() Mode Inspection',
          affectedResource: fullPath,
          observedAt: nowIso,
          description: `Configuration file "${fullPath}" has POSIX mode 0${mode.toString(8)} allowing world read/write access.`,
          impact: 'Local unprivileged accounts or compromised sibling services can read secrets or alter configuration.',
          remediation: `Restrict permissions to owner-only: chmod 600 "${fullPath}"`,
          evidence: { file: fullPath, detail: `mode 0${mode.toString(8)}` },
          cwe: 'CWE-732'
        });
      } else {
        inspectedChecks.push({
          id: `agent_perm_${fname}`,
          name: `File Permissions on ${fname}`,
          status: 'passed',
          detail: `Restrictive mode 0${mode.toString(8)}`
        });
      }

      if (fname.startsWith('.env')) {
        const raw = fs.readFileSync(fullPath, 'utf-8');
        if (/^\s*(?:DEBUG|APP_DEBUG)\s*=\s*(?:true|1)\s*$/im.test(raw)) {
          inspectedChecks.push({
            id: `agent_debug_${fname}`,
            name: `Production Debug Flag Check (${fname})`,
            status: 'failed',
            detail: 'DEBUG/APP_DEBUG enabled in environment file'
          });
          findings.push({
            checkId: `agent_debug_${fname}`,
            title: `Production Debug Flag Active in ${fname}`,
            severity: 'high',
            category: 'Code & Secrets',
            confidence: 'confirmed',
            accuracyTier: 'VERIFIED',
            detectionMethod: 'Read-Only Environment File Flag Inspection',
            affectedResource: fullPath,
            observedAt: nowIso,
            description: `Detected DEBUG/APP_DEBUG enabled inside "${fullPath}".`,
            impact: 'May expose verbose stack traces and environment variables in HTTP error responses.',
            remediation: 'Set DEBUG=false / APP_DEBUG=false in production.',
            evidence: { file: fullPath, detail: sanitizeText('DEBUG/APP_DEBUG=true') },
            cwe: 'CWE-489'
          });
        } else {
          inspectedChecks.push({
            id: `agent_debug_${fname}`,
            name: `Production Debug Flag Check (${fname})`,
            status: 'passed',
            detail: 'DEBUG/APP_DEBUG disabled or absent'
          });
        }
      }
    } catch (err) {
      inspectedChecks.push({
        id: `agent_perm_${fname}`,
        name: `File Permissions on ${fname}`,
        status: 'skipped',
        detail: err instanceof Error ? err.message : 'Unreadable file'
      });
    }
  }

  if (existingConfigFiles === 0) {
    inspectedChecks.push({
      id: 'agent_config_presence',
      name: 'Application Configuration Files Inspection',
      status: 'skipped',
      detail: `None of the expected configuration files (${sensitiveConfigFiles.join(', ')}) exist in ${dir}`
    });
  }

  return { findings, checkedPaths, inspectedChecks };
}

async function main() {
  const headers = getAuthHeaders();
  console.log(`[Site Sentinel Agent v2.1] Starting read-only inspection on ${os.hostname()} (${targetDir})`);
  await sendHeartbeat(headers);
  const { findings, checkedPaths, inspectedChecks } = inspectReadOnlyPosture(targetDir);

  const reportRes = await fetch(`${serverUrl}/api/v2/agent/report`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      hostname: os.hostname(),
      osPlatform: `${os.platform()} ${os.release()}`,
      runtimeVersion: process.version,
      checkedPaths,
      inspectedChecks,
      findings
    })
  });

  if (!reportRes.ok) {
    throw new Error(`Report upload failed (${reportRes.status}): ${await reportRes.text()}`);
  }
  const result = await reportRes.json();
  console.log(`[Site Sentinel Agent v2.1] Audit uploaded. Score: ${result.score}/100 (Grade ${result.grade}), Findings: ${result.findings?.length ?? 0}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error('[Site Sentinel Agent v2.1] Error:', err.message);
    process.exit(1);
  });
}
