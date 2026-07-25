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
