-- Per-task run budget: 0 keeps the previous behaviour, inheriting the process-wide
-- ARTEX_TASK_BUDGET_* setting. A positive value caps this task alone, so a
-- verification task can be bounded without shrinking every other task's allowance.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS budget_tokens BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS budget_turns BIGINT NOT NULL DEFAULT 0;
