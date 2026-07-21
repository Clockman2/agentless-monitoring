ALTER TABLE checks ADD COLUMN check_interval_seconds INTEGER NOT NULL DEFAULT 60
    CHECK (check_interval_seconds BETWEEN 10 AND 86400);
ALTER TABLE checks ADD COLUMN failure_threshold INTEGER NOT NULL DEFAULT 3
    CHECK (failure_threshold BETWEEN 1 AND 20);
ALTER TABLE checks ADD COLUMN recovery_threshold INTEGER NOT NULL DEFAULT 1
    CHECK (recovery_threshold BETWEEN 1 AND 20);
ALTER TABLE checks ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0
    CHECK (consecutive_failures >= 0);
ALTER TABLE checks ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0
    CHECK (consecutive_successes >= 0);

CREATE TABLE check_results (
    id INTEGER PRIMARY KEY,
    check_id INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('healthy', 'critical')),
    response_time_ms INTEGER NOT NULL CHECK (response_time_ms >= 0),
    error_category TEXT NOT NULL DEFAULT '' CHECK (length(error_category) <= 50),
    summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 500),
    worker TEXT NOT NULL CHECK (length(worker) BETWEEN 1 AND 100),
    checked_at TEXT NOT NULL
) STRICT;

CREATE INDEX checks_due_idx ON checks(enabled, last_checked_at);
CREATE INDEX check_results_check_time_idx ON check_results(check_id, checked_at DESC);
