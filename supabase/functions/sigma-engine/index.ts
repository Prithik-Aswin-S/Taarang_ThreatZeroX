import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { parse as parseYaml } from "jsr:@std/yaml@1.0.5";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface SigmaRule {
  title?: string;
  logsource?: Record<string, string>;
  detection?: {
    selection?: Record<string, unknown>;
    condition?: string;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

interface SecurityEvent {
  id: string;
  timestamp: string;
  category: string;
  is_malicious: boolean;
  [k: string]: unknown;
}

function validateSigma(yamlText: string): { valid: boolean; errors: string[]; warnings: string[]; rule?: SigmaRule } {
  const errors: string[] = [];
  const warnings: string[] = [];

  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    errors.push(`YAML parse error: ${(e as Error).message}`);
    return { valid: false, errors, warnings };
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    errors.push("Sigma rule must be a YAML mapping (object).");
    return { valid: false, errors, warnings };
  }

  const rule = parsed as SigmaRule;

  if (!rule.title || typeof rule.title !== "string") {
    errors.push("Missing required field: 'title' (string).");
  }
  if (!rule.logsource || typeof rule.logsource !== "object") {
    errors.push("Missing required field: 'logsource' (mapping).");
  } else if (!rule.logsource.category && !rule.logsource.product && !rule.logsource.service) {
    warnings.push("Logsource should specify 'category', 'product', or 'service'.");
  }
  if (!rule.detection || typeof rule.detection !== "object") {
    errors.push("Missing required field: 'detection' (mapping).");
    return { valid: errors.length === 0, errors, warnings, rule };
  }

  const det = rule.detection;
  if (!det.condition || typeof det.condition !== "string") {
    errors.push("Missing required field: 'detection.condition' (string).");
  }
  const selectionKeys = Object.keys(det).filter((k) => k !== "condition");
  if (selectionKeys.length === 0) {
    errors.push("No selection blocks found under 'detection'.");
  } else {
    for (const k of selectionKeys) {
      if (det[k] === null || typeof det[k] !== "object") {
        warnings.push(`Selection '${k}' should be a mapping or list of mappings.`);
      }
    }
  }

  if (det.condition && selectionKeys.length > 0) {
    for (const sk of selectionKeys) {
      if (!det.condition!.includes(sk)) {
        warnings.push(`Selection '${sk}' is defined but not referenced in condition.`);
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings, rule };
}

function getSelectionValues(sel: unknown): Record<string, unknown[]> {
  const out: Record<string, unknown[]> = {};
  const normalize = (v: unknown): unknown[] => (Array.isArray(v) ? v : [v]);
  if (Array.isArray(sel)) {
    for (const item of sel) {
      if (item && typeof item === "object") {
        for (const [k, v] of Object.entries(item as Record<string, unknown>)) {
          (out[k] ??= []).push(...normalize(v));
        }
      }
    }
  } else if (sel && typeof sel === "object") {
    for (const [k, v] of Object.entries(sel as Record<string, unknown>)) {
      out[k] = normalize(v);
    }
  }
  return out;
}

function eventMatchesSelection(evt: SecurityEvent, selValues: Record<string, unknown[]>): boolean {
  for (const [field, values] of Object.entries(selValues)) {
    const raw = (evt as Record<string, unknown>)[field];
    if (raw === undefined) return false;
    const evtStr = String(raw).toLowerCase();
    let matched = false;
    for (const v of values) {
      const vStr = String(v).toLowerCase();
      if (evtStr.includes(vStr)) {
        matched = true;
        break;
      }
    }
    if (!matched) return false;
  }
  return true;
}

function runRule(yamlText: string, events: SecurityEvent[]): {
  matches: number;
  matched_events: SecurityEvent[];
  precision: number;
  recall: number;
  false_positive_rate: number;
} {
  const { rule } = validateSigma(yamlText);
  if (!rule?.detection) {
    return { matches: 0, matched_events: [], precision: 0, recall: 0, false_positive_rate: 0 };
  }

  const det = rule.detection;
  const selectionKeys = Object.keys(det).filter((k) => k !== "condition");
  const matched: SecurityEvent[] = [];

  for (const evt of events) {
    let hit = false;
    for (const sk of selectionKeys) {
      const selValues = getSelectionValues(det[sk]);
      if (eventMatchesSelection(evt, selValues)) {
        hit = true;
        break;
      }
    }
    if (hit) matched.push(evt);
  }

  const tp = matched.filter((e) => e.is_malicious).length;
  const fp = matched.filter((e) => !e.is_malicious).length;
  const totalMalicious = events.filter((e) => e.is_malicious).length;
  const fn = Math.max(0, totalMalicious - tp);

  const precision = matched.length > 0 ? tp / matched.length : 0;
  const recall = totalMalicious > 0 ? tp / totalMalicious : 0;
  const fpr = events.length - totalMalicious > 0 ? fp / (events.length - totalMalicious) : 0;

  return {
    matches: matched.length,
    matched_events: matched,
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    false_positive_rate: Number(fpr.toFixed(4)),
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const route = url.pathname.replace(/.*\/sigma-engine/, "") || "/";
    const body = await req.json().catch(() => ({}));

    if (route === "/validate-rule" || route === "/") {
      const { yaml } = body as { yaml?: string };
      if (!yaml) {
        return new Response(JSON.stringify({ valid: false, errors: ["Missing 'yaml' field."], warnings: [] }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const result = validateSigma(yaml);
      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (route === "/run-rule") {
      const { yaml, events } = body as { yaml?: string; events?: SecurityEvent[] };
      if (!yaml || !Array.isArray(events)) {
        return new Response(JSON.stringify({ error: "Missing 'yaml' or 'events'." }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const result = runRule(yaml, events);
      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Unknown route. Use /validate-rule or /run-rule." }), {
      status: 404,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
