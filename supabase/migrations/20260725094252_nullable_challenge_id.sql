/*
# Make challenge_scores.challenge_id nullable

1. Modified Tables
   - challenge_scores: challenge_id is now nullable so scores can be recorded
     for static (code-defined) challenges that have no DB row.
2. Security
   - No policy changes.
*/

ALTER TABLE challenge_scores
  ALTER COLUMN challenge_id DROP NOT NULL;
