/*
# ThreatZero Sentinel X — Core Schema

1. Purpose
   Persistence layer for an AI-powered SOC detection engineering platform.
   Stores saved Sigma rules, security log datasets, detection incidents,
   academy challenges + scores, evidence vault records, and AI ML detections.

2. New Tables (creation order respects FK dependencies)
   - sigma_rules:        Saved Sigma detection rules authored in the lab.
   - datasets:           Security log dataset library (Windows/Sysmon/Web).
   - evidence:           Evidence vault records (hash, encryption status).
   - incidents:          Detection incidents (FK -> sigma_rules, evidence).
   - challenges:         Academy challenge definitions (FK -> datasets).
   - challenge_scores:   Per-challenge scores (FK -> challenges).
   - ai_detections:      ML detections with SHAP feature contributions.

3. Security
   - Single-tenant, no auth. RLS enabled on every table.
   - CRUD open to anon + authenticated (intentionally shared demo data).
*/

CREATE TABLE IF NOT EXISTS sigma_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  description text,
  yaml_content text NOT NULL,
  mitre_technique text,
  author text DEFAULT 'ThreatZero Sentinel X',
  status text DEFAULT 'draft',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS datasets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  category text NOT NULL,
  source_type text NOT NULL,
  description text,
  event_count integer DEFAULT 0,
  malicious_count integer DEFAULT 0,
  benign_count integer DEFAULT 0,
  events jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id text,
  evidence_hash text NOT NULL,
  attack_type text,
  mitre_technique text,
  encryption_status text DEFAULT 'AES-256 Protected',
  integrity_status text DEFAULT 'SHA-256 Integrity Verified',
  payload jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id text UNIQUE NOT NULL,
  timestamp timestamptz DEFAULT now(),
  attack_type text NOT NULL,
  mitre_technique text,
  severity text DEFAULT 'medium',
  threat_score numeric DEFAULT 0,
  status text DEFAULT 'open',
  rule_id uuid REFERENCES sigma_rules(id) ON DELETE SET NULL,
  matched_events jsonb DEFAULT '[]'::jsonb,
  ai_explanation text,
  recommended_actions jsonb DEFAULT '[]'::jsonb,
  evidence_id uuid REFERENCES evidence(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  mitre_technique text NOT NULL,
  tactic text,
  difficulty text DEFAULT 'medium',
  briefing text NOT NULL,
  dataset_id uuid REFERENCES datasets(id) ON DELETE SET NULL,
  starter_yaml text,
  target_precision numeric DEFAULT 0.9,
  target_recall numeric DEFAULT 0.9,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS challenge_scores (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id uuid REFERENCES challenges(id) ON DELETE CASCADE,
  analyst_name text DEFAULT 'Analyst',
  yaml_content text NOT NULL,
  precision numeric DEFAULT 0,
  recall numeric DEFAULT 0,
  false_positive_rate numeric DEFAULT 0,
  f1_score numeric DEFAULT 0,
  score integer DEFAULT 0,
  matches integer DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_detections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id text,
  attack_type text NOT NULL,
  mitre_technique text,
  threat_score numeric DEFAULT 0,
  confidence numeric DEFAULT 0,
  model_version text DEFAULT 'XGBoost-Sentinel-v2',
  shap_features jsonb DEFAULT '[]'::jsonb,
  suggested_sigma text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE sigma_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenge_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_detections ENABLE ROW LEVEL SECURITY;

-- sigma_rules policies
DROP POLICY IF EXISTS "anon_select_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_select_sigma_rules" ON sigma_rules FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_insert_sigma_rules" ON sigma_rules FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_update_sigma_rules" ON sigma_rules FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_delete_sigma_rules" ON sigma_rules FOR DELETE TO anon, authenticated USING (true);

-- datasets policies
DROP POLICY IF EXISTS "anon_select_datasets" ON datasets;
CREATE POLICY "anon_select_datasets" ON datasets FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_datasets" ON datasets;
CREATE POLICY "anon_insert_datasets" ON datasets FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_datasets" ON datasets;
CREATE POLICY "anon_update_datasets" ON datasets FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_datasets" ON datasets;
CREATE POLICY "anon_delete_datasets" ON datasets FOR DELETE TO anon, authenticated USING (true);

-- evidence policies
DROP POLICY IF EXISTS "anon_select_evidence" ON evidence;
CREATE POLICY "anon_select_evidence" ON evidence FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_evidence" ON evidence;
CREATE POLICY "anon_insert_evidence" ON evidence FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_evidence" ON evidence;
CREATE POLICY "anon_update_evidence" ON evidence FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_evidence" ON evidence;
CREATE POLICY "anon_delete_evidence" ON evidence FOR DELETE TO anon, authenticated USING (true);

-- incidents policies
DROP POLICY IF EXISTS "anon_select_incidents" ON incidents;
CREATE POLICY "anon_select_incidents" ON incidents FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_incidents" ON incidents;
CREATE POLICY "anon_insert_incidents" ON incidents FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_incidents" ON incidents;
CREATE POLICY "anon_update_incidents" ON incidents FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_incidents" ON incidents;
CREATE POLICY "anon_delete_incidents" ON incidents FOR DELETE TO anon, authenticated USING (true);

-- challenges policies
DROP POLICY IF EXISTS "anon_select_challenges" ON challenges;
CREATE POLICY "anon_select_challenges" ON challenges FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_challenges" ON challenges;
CREATE POLICY "anon_insert_challenges" ON challenges FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_challenges" ON challenges;
CREATE POLICY "anon_update_challenges" ON challenges FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_challenges" ON challenges;
CREATE POLICY "anon_delete_challenges" ON challenges FOR DELETE TO anon, authenticated USING (true);

-- challenge_scores policies
DROP POLICY IF EXISTS "anon_select_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_select_challenge_scores" ON challenge_scores FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_insert_challenge_scores" ON challenge_scores FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_update_challenge_scores" ON challenge_scores FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_delete_challenge_scores" ON challenge_scores FOR DELETE TO anon, authenticated USING (true);

-- ai_detections policies
DROP POLICY IF EXISTS "anon_select_ai_detections" ON ai_detections;
CREATE POLICY "anon_select_ai_detections" ON ai_detections FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_ai_detections" ON ai_detections;
CREATE POLICY "anon_insert_ai_detections" ON ai_detections FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_ai_detections" ON ai_detections;
CREATE POLICY "anon_update_ai_detections" ON ai_detections FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_ai_detections" ON ai_detections;
CREATE POLICY "anon_delete_ai_detections" ON ai_detections FOR DELETE TO anon, authenticated USING (true);
