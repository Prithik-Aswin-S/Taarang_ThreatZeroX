import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { parse as parseYaml } from "jsr:@std/yaml@1.0.5";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface SigmaRule {
  title?: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  level?: string;
  logsource?: Record<string, string>;
  detection?: {
    [k: string]: unknown;
  };
  tags?: string[];
  falsepositives?: string[];
  [k: string]: unknown;
}

interface SecurityEvent {
  id: string;
  timestamp: string;
  category: string;
  is_malicious: boolean;
  [k: string]: unknown;
}

interface ConfusionMatrix {
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
}

interface RunResult {
  matches: number;
  matched_events: SecurityEvent[];
  precision: number;
  recall: number;
  false_positive_rate: number;
  f1_score: number;
  accuracy: number;
  specificity: number;
  confusion_matrix: ConfusionMatrix;
  execution_time_ms: number;
}

// --- Sigma spec field modifier support ---
// Field names can be suffixed with |modifier. Supported: contains, startswith,
// endswith, re (regex), all (all values must match). Multiple modifiers chain.
function parseFieldKey(key: string): { field: string; modifiers: string[] } {
  const parts = key.split("|");
  return { field: parts[0], modifiers: parts.slice(1) };
}

function valueMatches(raw: unknown, expected: unknown, modifiers: string[]): boolean {
  if (raw === undefined || raw === null) return false;
  const evtStr = String(raw).toLowerCase();
  const expStr = String(expected).toLowerCase();

  if (modifiers.includes("re")) {
    try {
      const re = new RegExp(String(expected), "i");
      return re.test(String(raw));
    } catch {
      return evtStr.includes(expStr);
    }
  }
  if (modifiers.includes("contains")) return evtStr.includes(expStr);
  if (modifiers.includes("startswith")) return evtStr.startsWith(expStr);
  if (modifiers.includes("endswith")) return evtStr.endsWith(expStr);
  // exact match (default)
  return evtStr === expStr;
}

// Normalize a selection value into a list of {value, modifiers} entries.
function getSelectionEntries(sel: unknown): { values: unknown[]; modifiers: string[]; field: string }[] {
  // A selection can be a single mapping, or a list of mappings (OR semantics).
  // Each mapping has field keys (with optional modifiers) -> scalar or list.
  const entries: { values: unknown[]; modifiers: string[]; field: string }[] = [];
  const handleMapping = (m: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(m)) {
      const { field, modifiers } = parseFieldKey(k);
      const values = Array.isArray(v) ? v : [v];
      entries.push({ values, modifiers, field });
    }
  };
  if (Array.isArray(sel)) {
    for (const item of sel) {
      if (item && typeof item === "object") handleMapping(item as Record<string, unknown>);
    }
  } else if (sel && typeof sel === "object") {
    handleMapping(sel as Record<string, unknown>);
  }
  return entries;
}

function eventMatchesSelection(evt: SecurityEvent, sel: unknown): boolean {
  const entries = getSelectionEntries(sel);
  if (entries.length === 0) return false;
  // All entries must match (AND within a single selection block).
  for (const entry of entries) {
    let fieldMatched = false;
    for (const v of entry.values) {
      const raw = (evt as Record<string, unknown>)[entry.field];
      if (valueMatches(raw, v, entry.modifiers)) {
        fieldMatched = true;
        break;
      }
    }
    if (!fieldMatched) return false;
  }
  return true;
}

// --- Condition parser ---
// Supports: selection names, AND, OR, NOT, and 1-of (selection). Parentheses
// are supported for grouping. This is a small recursive-descent parser.
type Token = { type: "ident" | "and" | "or" | "not" | "lparen" | "rparen" | "of" | "number" | "ofkw"; value: string };

function tokenizeCondition(cond: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const keywords = new Set(["and", "or", "not", "of"]);
  while (i < cond.length) {
    const ch = cond[i];
    if (ch === " " || ch === "\t") { i++; continue; }
    if (ch === "(") { tokens.push({ type: "lparen", value: ch }); i++; continue; }
    if (ch === ")") { tokens.push({ type: "rparen", value: ch }); i++; continue; }
    // number (for 1-of syntax)
    if (/[0-9]/.test(ch)) {
      let num = "";
      while (i < cond.length && /[0-9]/.test(cond[i])) { num += cond[i]; i++; }
      tokens.push({ type: "number", value: num });
      continue;
    }
    // identifier or keyword
    if (/[A-Za-z_]/.test(ch)) {
      let id = "";
      while (i < cond.length && /[A-Za-z0-9_]/.test(cond[i])) { id += cond[i]; i++; }
      const lower = id.toLowerCase();
      if (keywords.has(lower)) {
        tokens.push({ type: lower as Token["type"], value: id });
      } else {
        tokens.push({ type: "ident", value: id });
      }
      continue;
    }
    i++;
  }
  return tokens;
}

class ConditionParser {
  private pos = 0;
  constructor(private tokens: Token[]) {}

  private peek(): Token | undefined { return this.tokens[this.pos]; }
  private next(): Token | undefined { return this.tokens[this.pos++]; }

  // expr := orExpr
  // orExpr := andExpr (OR andExpr)*
  // andExpr := notExpr (AND notExpr)*
  // notExpr := NOT notExpr | primary
  // primary := ident (OF)? | ( expr ) | number-of selections
  parse(): (selections: Record<string, unknown>) => boolean {
    return this.parseOr();
  }

  private parseOr(): (s: Record<string, unknown>) => boolean {
    let left = this.parseAnd();
    while (this.peek()?.type === "or") {
      this.next();
      const right = this.parseAnd();
      const l = left; const r = right;
      left = (s) => l(s) || r(s);
    }
    return left;
  }

  private parseAnd(): (s: Record<string, unknown>) => boolean {
    let left = this.parseNot();
    while (this.peek()?.type === "and") {
      this.next();
      const right = this.parseNot();
      const l = left; const r = right;
      left = (s) => l(s) && r(s);
    }
    return left;
  }

  private parseNot(): (s: Record<string, unknown>) => boolean {
    if (this.peek()?.type === "not") {
      this.next();
      const inner = this.parseNot();
      return (s) => !inner(s);
    }
    return this.parsePrimary();
  }

  private parsePrimary(): (s: Record<string, unknown>) => boolean {
    const tok = this.peek();
    if (tok?.type === "lparen") {
      this.next();
      const inner = this.parseOr();
      if (this.peek()?.type === "rparen") this.next();
      return inner;
    }
    if (tok?.type === "number") {
      // N-of syntax: "1 of selection" or "1 of them"
      this.next();
      if (this.peek()?.type === "of") {
        this.next();
        const target = this.next();
        const n = parseInt(tok.value, 10);
        const targetName = target?.value ?? "them";
        return (s) => {
          const keys = targetName === "them" ? Object.keys(s) : [targetName];
          let matched = 0;
          for (const k of keys) {
            if (eventMatchesSelectionRaw(s[k])) matched++;
          }
          return matched >= n;
        };
      }
    }
    if (tok?.type === "ident") {
      this.next();
      const name = tok.value;
      // Check for "of" keyword: "selection of" is not standard; skip.
      return (s) => {
        const sel = s[name];
        if (sel === undefined) return false;
        return eventMatchesSelectionRaw(sel);
      };
    }
    // fallback: always false
    this.next();
    return () => false;
  }
}

// Wrapper to evaluate a selection block against the current event context.
// We use a closure trick: the condition evaluator calls eventMatchesSelectionRaw
// with the selection definition, but we need the event. We restructure: instead
// of passing selections, we pre-bind the event.
let currentEvent: SecurityEvent | null = null;
function eventMatchesSelectionRaw(sel: unknown): boolean {
  if (!currentEvent) return false;
  return eventMatchesSelection(currentEvent, sel);
}

// --- Validation ---
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
      if (det[k] === null || (typeof det[k] !== "object" && !Array.isArray(det[k]))) {
        warnings.push(`Selection '${k}' should be a mapping or list of mappings.`);
      }
    }
  }

  if (det.condition && selectionKeys.length > 0) {
    // Validate condition syntax by tokenizing + parsing.
    const condStr = det.condition as string;
    const tokens = tokenizeCondition(condStr);
    try {
      const parser = new ConditionParser(tokens);
      const fn = parser.parse();
      // sanity: referenced idents should exist
      const idents = tokens.filter((t) => t.type === "ident").map((t) => t.value);
      for (const id of idents) {
        if (id !== "them" && !selectionKeys.includes(id)) {
          warnings.push(`Condition references '${id}' which is not a defined selection.`);
        }
      }
      // test it doesn't throw
      fn(Object.fromEntries(selectionKeys.map((k) => [k, det[k]])));
    } catch (e) {
      errors.push(`Condition parse error: ${(e as Error).message}`);
    }
    for (const sk of selectionKeys) {
      if (!condStr.includes(sk) && !condStr.includes("them")) {
        warnings.push(`Selection '${sk}' is defined but not referenced in condition.`);
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings, rule };
}

// --- Rule execution with confusion matrix ---
function runRule(yamlText: string, events: SecurityEvent[]): RunResult {
  const start = performance.now();
  const { rule } = validateSigma(yamlText);
  if (!rule?.detection) {
    return {
      matches: 0, matched_events: [], precision: 0, recall: 0,
      false_positive_rate: 0, f1_score: 0, accuracy: 0, specificity: 0,
      confusion_matrix: { true_positives: 0, false_positives: 0, true_negatives: 0, false_negatives: 0 },
      execution_time_ms: 0,
    };
  }

  const det = rule.detection;
  const condStr = (det.condition as string) ?? "";
  const selectionKeys = Object.keys(det).filter((k) => k !== "condition");
  const selections: Record<string, unknown> = {};
  for (const k of selectionKeys) selections[k] = det[k];

  let evaluator: ((s: Record<string, unknown>) => boolean) | null = null;
  if (condStr) {
    const tokens = tokenizeCondition(condStr);
    const parser = new ConditionParser(tokens);
    evaluator = parser.parse();
  }

  const matched: SecurityEvent[] = [];
  for (const evt of events) {
    currentEvent = evt;
    let hit = false;
    if (evaluator) {
      hit = evaluator(selections);
    } else {
      // fallback: OR all selections
      for (const sk of selectionKeys) {
        if (eventMatchesSelection(evt, selections[sk])) { hit = true; break; }
      }
    }
    if (hit) matched.push(evt);
  }
  currentEvent = null;

  const tp = matched.filter((e) => e.is_malicious).length;
  const fp = matched.filter((e) => !e.is_malicious).length;
  const totalMalicious = events.filter((e) => e.is_malicious).length;
  const totalBenign = events.length - totalMalicious;
  const fn = Math.max(0, totalMalicious - tp);
  const tn = Math.max(0, totalBenign - fp);

  const precision = matched.length > 0 ? tp / matched.length : 0;
  const recall = totalMalicious > 0 ? tp / totalMalicious : 0;
  const fpr = totalBenign > 0 ? fp / totalBenign : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = events.length > 0 ? (tp + tn) / events.length : 0;
  const specificity = totalBenign > 0 ? tn / totalBenign : 0;

  return {
    matches: matched.length,
    matched_events: matched,
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    false_positive_rate: Number(fpr.toFixed(4)),
    f1_score: Number(f1.toFixed(4)),
    accuracy: Number(accuracy.toFixed(4)),
    specificity: Number(specificity.toFixed(4)),
    confusion_matrix: { true_positives: tp, false_positives: fp, true_negatives: tn, false_negatives: fn },
    execution_time_ms: Math.round(performance.now() - start),
  };
}

// --- Simulated log datasets (served from edge for /log-datasets) ---
const DATASETS = [
  {
    id: "ds-windows",
    name: "Windows Security Event Logs",
    category: "Windows Security",
    source_type: "Windows Event Log",
    description: "Windows Security events: 4624 (logon), 4625 (logon fail), 4688 (process creation), 4698 (scheduled task), 7045 (service install). Benign + malicious.",
    event_types: ["4624", "4625", "4688", "4698", "7045"],
  },
  {
    id: "ds-sysmon",
    name: "Sysmon Logs",
    category: "Sysmon",
    source_type: "Sysmon",
    description: "Sysmon EID 1 (process), EID 3 (network), EID 11 (file). Includes encoded PowerShell, LSASS access, C2 beaconing.",
    event_types: ["1", "3", "11"],
  },
  {
    id: "ds-web",
    name: "Web Access Logs",
    category: "Web Access",
    source_type: "HTTP",
    description: "Web server access logs with SQL injection, command injection, and normal traffic.",
    event_types: ["HTTP"],
  },
];

const CHALLENGES_META = [
  { id: "ch1-powershell", title: "Encoded PowerShell Execution", mitre: "T1059.001", tactic: "Execution", difficulty: "Medium" },
  { id: "ch2-lsass", title: "LSASS Credential Access", mitre: "T1003", tactic: "Credential Access", difficulty: "Hard" },
  { id: "ch3-schtasks", title: "Scheduled Task Creation", mitre: "T1053", tactic: "Execution", difficulty: "Medium" },
  { id: "ch4-pth", title: "Pass The Hash Detection", mitre: "T1550", tactic: "Lateral Movement", difficulty: "Expert" },
  { id: "ch5-sqli", title: "SQL Injection Detection", mitre: "T1190", tactic: "Initial Access", difficulty: "Medium" },
];

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const route = url.pathname.replace(/.*\/sigma-engine/, "") || "/";

    if (route === "/log-datasets" && req.method === "GET") {
      return new Response(JSON.stringify({ datasets: DATASETS }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (route === "/challenges" && req.method === "GET") {
      return new Response(JSON.stringify({ challenges: CHALLENGES_META }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

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

    return new Response(JSON.stringify({ error: "Unknown route. Use /validate-rule, /run-rule, /log-datasets, or /challenges." }), {
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
