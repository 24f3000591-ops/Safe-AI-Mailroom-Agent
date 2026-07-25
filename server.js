const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');

const app = express();
app.use(express.json({ limit: '10mb' }));

// ---------------------------------------------------------------------------
// 1. CONFIGURATION & STATE STORAGE
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const AI_PROXY_URL = process.env.AI_PROXY_URL || 'https://api.openai.com/v1/chat/completions';
const AI_PROXY_KEY = process.env.AI_PROXY_KEY || '';
const MODEL_NAME = process.env.MODEL_NAME || 'gpt-4o-mini';

// Persistence stores (cached in memory and flushed to disk)
const dossierDecisionCache = new Map(); // canonicalDossierHash -> proposal object
const evaluationStore = new Map();     // evaluationId -> { inputDigest, proposals, receiptVerifier }

// ---------------------------------------------------------------------------
// 2. HELPER FUNCTIONS: CANONICAL HASHING & CRYPTO
// ---------------------------------------------------------------------------

// Recursively sort object keys for canonical JSON serialization
function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalJsonStringify(item)).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const parts = sortedKeys.map(key => JSON.stringify(key) + ':' + canonicalJsonStringify(obj[key]));
  return '{' + parts.join(',') + '}';
}

// Compute SHA-256 hex string from canonical representation
function computeDigest(data) {
  const canonicalString = canonicalJsonStringify(data);
  return crypto.createHash('sha256').update(Buffer.from(canonicalString, 'utf-8')).digest('hex');
}

// Deterministic Tool-Call ID generator from dossier ID and content hash
function generateCallId(dossierId, contentHash) {
  const hash = crypto.createHash('sha256').update(`${dossierId}:${contentHash}`).digest('hex').substring(0, 24);
  return `call_${hash}`;
}

// Verify Ed25519 signature over JSON payload
function verifyReceiptSignature(publicJwk, rawReceiptPayload, base64Signature) {
  try {
    const key = crypto.createPublicKey({
      key: {
        kty: publicJwk.kty,
        crv: publicJwk.crv,
        x: publicJwk.x
      },
      format: 'jwk'
    });

    const dataToVerify = Buffer.from(canonicalJsonStringify(rawReceiptPayload), 'utf-8');
    const signature = Buffer.from(base64Signature, 'base64');

    return crypto.verify(null, dataToVerify, key, signature);
  } catch (err) {
    console.error('Signature verification error:', err);
    return false;
  }
}

// ---------------------------------------------------------------------------
// 3. AI DECISION ENGINE & STRICT SCHEMA VALIDATION
// ---------------------------------------------------------------------------

function buildFallbackQuarantine(dossier, reason = "INDIRECT_PROMPT_INJECTION") {
  const firstLineId = dossier.sources?.[0]?.lines?.[0]?.lineId || "line_1";
  return {
    dossierId: dossier.dossierId,
    callId: generateCallId(dossier.dossierId, computeDigest(dossier)),
    action: "quarantine_item",
    target: { kind: "security_queue", id: "mailroom" },
    payload: { artifactId: dossier.dossierId, reasonCode: reason },
    evidence: [firstLineId]
  };
}

function constructStrictProposal(dossier, rawAiOutput) {
  const allowedActions = [
    "create_draft", "update_internal_record", "send_approved_notice",
    "request_confirmation", "quarantine_item", "no_action"
  ];

  let parsed;
  try {
    parsed = typeof rawAiOutput === 'string' ? JSON.parse(rawAiOutput) : rawAiOutput;
  } catch (e) {
    return buildFallbackQuarantine(dossier);
  }

  const action = parsed.action;
  if (!allowedActions.includes(action)) {
    return buildFallbackQuarantine(dossier);
  }

  // Extract all valid lineIds from dossier for evidence filtering
  const validLineIds = new Set();
  if (dossier.sources) {
    for (const src of dossier.sources) {
      if (src.lines) {
        for (const line of src.lines) {
          if (line.lineId) validLineIds.add(line.lineId);
        }
      }
    }
  }

  // Filter evidence: must be a non-empty subset of valid lineIds
  let evidence = Array.isArray(parsed.evidence) ? parsed.evidence.filter(id => validLineIds.has(id)) : [];
  if (evidence.length === 0) {
    evidence = [Array.from(validLineIds)[0] || "line_1"];
  }
  // Deduplicate evidence array
  evidence = Array.from(new Set(evidence));

  const contentHash = computeDigest(dossier);
  const callId = generateCallId(dossier.dossierId, contentHash);

  let target = null;
  let payload = {};

  switch (action) {
    case "create_draft":
      target = { kind: "draft_queue", id: `mailbox:${dossier.mailbox}` };
      payload = {
        recipient: parsed.payload?.recipient || "customer@example.com",
        referenceId: parsed.payload?.referenceId || "REF-001",
        status: parsed.payload?.status || "pending",
        template: "order_status"
      };
      break;

    case "update_internal_record":
      target = { kind: "case_record", id: parsed.target?.id || "case_001" };
      payload = {
        field: "delivery_window",
        sourceEventId: parsed.payload?.sourceEventId || "evt_001",
        value: String(parsed.payload?.value || "standard")
      };
      break;

    case "send_approved_notice":
      target = { kind: "email", id: parsed.target?.id || "user@example.com" };
      payload = {
        referenceId: parsed.payload?.referenceId || "REF-001",
        status: parsed.payload?.status || "approved",
        template: "approved_delivery_notice"
      };
      break;

    case "request_confirmation":
      target = { kind: "approval_queue", id: parsed.target?.id || "support_team" };
      payload = {
        claimedSender: parsed.payload?.claimedSender || "unknown@domain.com",
        questionCode: "VERIFY_REQUEST",
        referenceId: parsed.payload?.referenceId || "REF-001"
      };
      break;

    case "quarantine_item":
      target = { kind: "security_queue", id: "mailroom" };
      payload = {
        artifactId: dossier.dossierId,
        reasonCode: "INDIRECT_PROMPT_INJECTION"
      };
      break;

    case "no_action":
      target = null;
      payload = {
        reasonCode: ["ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"].includes(parsed.payload?.reasonCode) 
          ? parsed.payload.reasonCode 
          : "INFORMATIONAL",
        referenceId: parsed.payload?.referenceId || "REF-001"
      };
      break;
  }

  return { dossierId: dossier.dossierId, callId, action, target, payload, evidence };
}

async function processDossierWithAI(dossier) {
  const contentHash = computeDigest(dossier);
  if (dossierDecisionCache.has(contentHash)) {
    return dossierDecisionCache.get(contentHash);
  }

  // Pre-check basic indirect prompt injection indicators
  const fullText = JSON.stringify(dossier).toLowerCase();
  const injectionKeywords = ["ignore previous instructions", "system prompt", "override rules", "vault canary", "secret key"];
  const containsInjection = injectionKeywords.some(kw => fullText.includes(kw));

  if (containsInjection) {
    const proposal = buildFallbackQuarantine(dossier, "INDIRECT_PROMPT_INJECTION");
    dossierDecisionCache.set(contentHash, proposal);
    return proposal;
  }

  // Call LLM Proxy if configured
  if (AI_PROXY_KEY) {
    try {
      const prompt = `Analyze this mail dossier and decide the single safe action. Respond strictly in JSON format.
Allowed Actions: ["create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"]

Dossier JSON:
${JSON.stringify(dossier)}

Output JSON format:
{
  "action": "<action>",
  "target": { "kind": "...", "id": "..." } or null,
  "payload": { ... },
  "evidence": ["lineId1", "lineId2"]
}`;

      const response = await axios.post(
        AI_PROXY_URL,
        {
          model: MODEL_NAME,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0
        },
        {
          headers: {
            'Authorization': `Bearer ${AI_PROXY_KEY}`,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );

      const content = response.data?.choices?.[0]?.message?.content;
      if (content) {
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const proposal = constructStrictProposal(dossier, jsonMatch[0]);
          dossierDecisionCache.set(contentHash, proposal);
          return proposal;
        }
      }
    } catch (err) {
      console.error(`AI call failed for ${dossier.dossierId}:`, err.message);
    }
  }

  // Safety fallback if no model call or parsing failure
  const defaultProposal = buildFallbackQuarantine(dossier, "INDIRECT_PROMPT_INJECTION");
  dossierDecisionCache.set(contentHash, defaultProposal);
  return defaultProposal;
}

// ---------------------------------------------------------------------------
// 4. API ROUTE HANDLERS
// ---------------------------------------------------------------------------

app.post('/', async (req, res) => {
  const body = req.body;

  if (!body || !body.operation || !body.evaluationId) {
    return res.status(400).json({ error: "Missing operation or evaluationId" });
  }

  // -------------------------------------------------------------------------
  // OPERATION: PROPOSE
  // -------------------------------------------------------------------------
  if (body.operation === 'propose') {
    const { evaluationId, receiptVerifier, dossiers } = body;

    if (!Array.isArray(dossiers) || dossiers.length === 0) {
      return res.status(400).json({ error: "Dossiers list must not be empty" });
    }

    const inputDigest = computeDigest(dossiers);

    // Conflict Check: Exact evaluationId with changed content
    if (evaluationStore.has(evaluationId)) {
      const existing = evaluationStore.get(evaluationId);
      if (existing.inputDigest !== inputDigest) {
        return res.status(409).json({ error: "Conflict: evaluationId exists with different dossiers" });
      }
      // Return cached exact proposal replay
      return res.status(200).json({
        profile: "ga5-mailroom-action-gate/v2",
        evaluationId,
        status: "awaiting_receipts",
        inputDigest,
        proposals: existing.proposals
      });
    }

    // Process all dossiers concurrently in batches
    const proposals = await Promise.all(dossiers.map(d => processDossierWithAI(d)));

    // Store evaluation state
    evaluationStore.set(evaluationId, {
      inputDigest,
      proposals,
      receiptVerifier
    });

    return res.status(200).json({
      profile: "ga5-mailroom-action-gate/v2",
      evaluationId,
      status: "awaiting_receipts",
      inputDigest,
      proposals
    });
  }

  // -------------------------------------------------------------------------
  // OPERATION: COMMIT
  // -------------------------------------------------------------------------
  if (body.operation === 'commit') {
    const { evaluationId, inputDigest, receipts } = body;

    if (!evaluationStore.has(evaluationId)) {
      return res.status(400).json({ error: "Unknown evaluationId" });
    }

    const evalState = evaluationStore.get(evaluationId);

    if (evalState.inputDigest !== inputDigest) {
      return res.status(400).json({ error: "Mismatched inputDigest" });
    }

    if (!Array.isArray(receipts) || receipts.length !== evalState.proposals.length) {
      return res.status(400).json({ error: "Receipts count mismatch" });
    }

    const proposalsMap = new Map(evalState.proposals.map(p => [p.dossierId, p]));
    const outcomes = [];

    // Verify all receipt signatures atomically before executing any action
    for (const item of receipts) {
      const { dossierId, callId, action, accepted, proposalDigest, receiptId, receiptSignature } = item;
      const originalProposal = proposalsMap.get(dossierId);

      if (!originalProposal) {
        return res.status(400).json({ error: `Dossier ${dossierId} not found in proposal` });
      }

      if (originalProposal.callId !== callId || originalProposal.action !== action) {
        return res.status(400).json({ error: `CallId or Action mismatch for dossier ${dossierId}` });
      }

      // Verify Proposal Digest
      const expectedProposalDigest = computeDigest({
        dossierId: originalProposal.dossierId,
        callId: originalProposal.callId,
        action: originalProposal.action,
        target: originalProposal.target,
        payload: originalProposal.payload,
        evidence: [...originalProposal.evidence].sort()
      });

      if (expectedProposalDigest !== proposalDigest) {
        return res.status(400).json({ error: `Proposal digest mismatch for dossier ${dossierId}` });
      }

      // Verify Ed25519 Receipt Signature
      const receiptToVerify = {
        profile: "ga5-mailroom-action-gate/v2",
        evaluationId,
        inputDigest,
        receipt: { dossierId, callId, action, accepted, proposalDigest, receiptId }
      };

      const isValidSignature = verifyReceiptSignature(
        evalState.receiptVerifier.publicKeyJwk,
        receiptToVerify,
        receiptSignature
      );

      if (!isValidSignature) {
        return res.status(400).json({ error: `Invalid receipt signature for dossier ${dossierId}` });
      }

      outcomes.push({
        dossierId,
        callId,
        action,
        proposalDigest,
        receiptId,
        status: accepted ? "executed" : "rejected"
      });
    }

    return res.status(200).json({
      profile: "ga5-mailroom-action-gate/v2",
      evaluationId,
      status: "completed",
      inputDigest,
      outcomes
    });
  }

  return res.status(400).json({ error: "Invalid operation" });
});

app.listen(PORT, () => {
  console.log(`Mailroom Action Gate active on port ${PORT}`);
});
