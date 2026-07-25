const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods":
    "POST, GET, OPTIONS",
};

export interface SigmaRule {
  id: string;
  title: string;
  description: string | null;
  yaml_content: string;
  mitre_technique: string | null;
  author: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  category: string;
  is_malicious: boolean;
  [key: string]: unknown;
}

export interface Dataset {
  id: string;
  name: string;
  category: string;
  source_type: string;
  description: string | null;
  event_count: number;
  malicious_count: number;
  benign_count: number;
  events: SecurityEvent[];
  created_at: string;
}

export interface Incident {
  id: string;
  incident_id: string;
  timestamp: string;
  attack_type: string;
  mitre_technique: string | null;
  severity: string;
  threat_score: number;
  status: string;
  rule_id: string | null;
  matched_events: SecurityEvent[];
  ai_explanation: string | null;
  recommended_actions: string[];
  evidence_id: string | null;
  created_at: string;
}

export interface Challenge {
  id: string;
  title: string;
  mitre_technique: string;
  tactic: string | null;
  difficulty: string;
  briefing: string;
  dataset_id: string | null;
  starter_yaml: string | null;
  target_precision: number;
  target_recall: number;
  created_at: string;
}

export interface ChallengeScore {
  id: string;
  challenge_id: string;
  analyst_name: string;
  yaml_content: string;
  precision: number;
  recall: number;
  false_positive_rate: number;
  f1_score: number;
  score: number;
  matches: number;
  created_at: string;
}

export interface Evidence {
  id: string;
  incident_id: string | null;
  evidence_hash: string;
  attack_type: string | null;
  mitre_technique: string | null;
  encryption_status: string;
  integrity_status: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AiDetection {
  id: string;
  event_id: string | null;
  attack_type: string;
  mitre_technique: string | null;
  threat_score: number;
  confidence: number;
  model_version: string;
  shap_features: ShapFeature[];
  suggested_sigma: string | null;
  created_at: string;
}

export interface ShapFeature {
  feature: string;
  contribution: number;
}

export interface ValidationResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
  rule?: unknown;
}

export interface ConfusionMatrix {
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
}

export interface RunRuleResponse {
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

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}