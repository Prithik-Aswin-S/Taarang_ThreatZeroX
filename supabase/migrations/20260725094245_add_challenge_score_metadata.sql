/*
# Add metadata columns to challenge_scores

1. Modified Tables
   - challenge_scores: add challenge_title (text) and mitre_technique (text)
     so scores can be recorded for static (code-defined) challenges without
     requiring a FK challenge_id. challenge_id remains nullable.
2. Security
   - No policy changes; existing anon CRUD policies still apply.
*/

ALTER TABLE challenge_scores
  ADD COLUMN IF NOT EXISTS challenge_title text,
  ADD COLUMN IF NOT EXISTS mitre_technique text;
