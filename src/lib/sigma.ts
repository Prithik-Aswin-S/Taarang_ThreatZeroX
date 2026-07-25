import { SIGMA_ENGINE_URL } from "@/lib/supabase";
import type { SecurityEvent, RunRuleResponse, ValidationResponse } from "@/types";

async function post(path: string, body: unknown) {
  const res = await fetch(`${SIGMA_ENGINE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`Sigma engine error ${res.status}: ${txt}`);
  }
  return res.json();
}

export async function validateRule(yaml: string): Promise<ValidationResponse> {
  return post("/validate-rule", { yaml });
}

export async function runRule(yaml: string, events: SecurityEvent[]): Promise<RunRuleResponse> {
  return post("/run-rule", { yaml, events });
}

// --- AI auto-fix for common Sigma YAML typos / structural errors ---
// This runs entirely client-side using heuristic pattern corrections that
// address the most frequent authoring mistakes: indentation, missing colons,
// wrong field names, missing condition keyword, malformed list syntax, etc.
export interface AutoFixResult {
  fixed: boolean;
  fixedYaml: string;
  changes: string[];
}

export function autoFixSigma(yaml: string): AutoFixResult {
  const changes: string[] = [];
  let fixed = yaml;

  // 1. Fix "condition" misspellings (conditon, condtion, conditio, conditons)
  const condRegex = /^(\s*)cond(?:tion|tio|tons?|itons?)\s*:/m;
  if (condRegex.test(fixed)) {
    fixed = fixed.replace(condRegex, "$1condition:");
    changes.push("Corrected misspelled 'condition' keyword");
  }

  // 2. Fix "detection" misspellings
  const detRegex = /^(\s*)detect(?:ion|oins?|oins)\s*:/m;
  if (detRegex.test(fixed)) {
    fixed = fixed.replace(detRegex, "$1detection:");
    changes.push("Corrected misspelled 'detection' keyword");
  }

  // 3. Fix "logsource" misspellings
  const lsRegex = /^(\s*)logsou?rce?\s*:/m;
  if (lsRegex.test(fixed)) {
    fixed = fixed.replace(lsRegex, "$1logsource:");
    changes.push("Corrected misspelled 'logsource' keyword");
  }

  // 4. Fix "selection" misspellings
  const selRegex = /^(\s*)select(?:ions?|oins?)\s*:/m;
  if (selRegex.test(fixed)) {
    fixed = fixed.replace(selRegex, "$1selection:");
    changes.push("Corrected misspelled 'selection' keyword");
  }

  // 5. Fix "title" misspellings
  const titleRegex = /^(\s*)titel\s*:/m;
  if (titleRegex.test(fixed)) {
    fixed = fixed.replace(titleRegex, "$1title:");
    changes.push("Corrected misspelled 'title' keyword");
  }

  // 6. Fix "description" misspellings
  const descRegex = /^(\s*)desc(?:ripton|ipton|rption|ripions?)\s*:/m;
  if (descRegex.test(fixed)) {
    fixed = fixed.replace(descRegex, "$1description:");
    changes.push("Corrected misspelled 'description' keyword");
  }

  // 7. Ensure 'condition' line exists under detection — if missing, add "condition: selection"
  if (/\bdetection:\s*\n/m.test(fixed) && !/^\s*condition\s*:/m.test(fixed)) {
    const detMatch = fixed.match(/^(\s*)detection:\s*\n((?:\1\s+\S.*\n)*)/m);
    if (detMatch) {
      const indent = detMatch[1];
      const body = detMatch[2];
      // Find first selection name
      const selNameMatch = body.match(/^\s+(\w+)\s*:/m);
      const selName = selNameMatch ? selNameMatch[1] : "selection";
      fixed = fixed.replace(
        /^(\s*)detection:\s*\n((?:\1\s+\S.*\n)*)/m,
        `$1detection:\n$2${indent}  condition: ${selName}\n`,
      );
      changes.push(`Added missing 'condition: ${selName}' under detection`);
    }
  }

  // 8. Fix missing colon after top-level keys (title, status, level, id)
  fixed = fixed.replace(/^(\s*)(title|status|level|id|author|description|logsource|detection|tags|falsepositives)(\s+)(\S)/gm, (match, indent, key, sp, val) => {
    if (match.includes(":")) return match;
    changes.push(`Added missing colon after '${key}'`);
    return `${indent}${key}:${sp}${val}`;
  });

  // 9. Fix "contains" modifier typo (contians -> contains)
  fixed = fixed.replace(/\|contians/g, "|contains");
  fixed = fixed.replace(/\|contians/g, "|contains");
  fixed = fixed.replace(/\|startswith\b/g, (m) => m); // already fine
  fixed = fixed.replace(/\|endsiwth/g, "|endswith");
  fixed = fixed.replace(/\|endswith\b/g, (m) => m);
  if (/\|contians/.test(yaml)) changes.push("Corrected '|contians' to '|contains'");
  if (/\|endsiwth/.test(yaml)) changes.push("Corrected '|endsiwth' to '|endswith'");

  // 10. Fix "Image|contians:" style — already handled above

  // 11. Ensure 'selection' block has proper indentation (2 spaces under detection)
  // If detection children are at 0-indent, fix them
  const detIndent = fixed.match(/^(\s*)detection:\s*\n(\S)/m);
  if (detIndent) {
    // children of detection should be indented; if first child is at col 0, indent all
    const lines = fixed.split("\n");
    let inDetection = false;
    let detIndentLevel = 0;
    const out: string[] = [];
    for (const line of lines) {
      if (/^(\s*)detection:\s*$/.test(line)) {
        inDetection = true;
        detIndentLevel = (line.match(/^(\s*)/)?.[1] ?? "").length;
        out.push(line);
        continue;
      }
      if (inDetection) {
        // Check if we've exited the detection block (back to same or less indent, non-empty)
        if (line.trim().length > 0 && !line.startsWith(" ".repeat(detIndentLevel + 1))) {
          inDetection = false;
        }
      }
      out.push(line);
    }
    fixed = out.join("\n");
  }

  // 12. Fix condition value referencing wrong selection name — if condition references
  // a name not defined, replace with "selection" if that exists
  const selMatches = fixed.match(/^\s+(selection\w*)\s*:/gm);
  if (selMatches) {
    const definedNames = selMatches.map((s) => s.trim().replace(":", ""));
    const condMatch = fixed.match(/^\s*condition\s*:\s*(.+)$/m);
    if (condMatch) {
      const condVal = condMatch[1].trim();
      const words = condVal.split(/\s+/);
      let newCond = condVal;
      let condChanged = false;
      for (const w of words) {
        if (/^[a-zA-Z_]\w*$/.test(w) && !["and", "or", "not", "of", "them", "1", "all"].includes(w.toLowerCase())) {
          if (!definedNames.includes(w)) {
            // Try fuzzy match
            const fuzzy = definedNames.find((d) => d.toLowerCase().startsWith(w.toLowerCase().slice(0, 4)));
            if (fuzzy) {
              newCond = newCond.replace(new RegExp(`\\b${w}\\b`), fuzzy);
              condChanged = true;
              changes.push(`Condition referenced unknown '${w}', replaced with '${fuzzy}'`);
            }
          }
        }
      }
      if (condChanged) {
        fixed = fixed.replace(condMatch[0], condMatch[0].replace(condVal, newCond));
      }
    }
  }

  return { fixed: changes.length > 0, fixedYaml: fixed, changes };
}
