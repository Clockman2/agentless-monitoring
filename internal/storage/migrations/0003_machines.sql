CREATE TABLE machines (
    id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    target TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('healthy', 'critical', 'unknown', 'disabled')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE checks (
    id INTEGER PRIMARY KEY,
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    check_type TEXT NOT NULL CHECK (check_type IN ('tcp', 'http', 'https')),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    path TEXT NOT NULL DEFAULT '/' CHECK (length(path) BETWEEN 1 AND 256),
    timeout_ms INTEGER NOT NULL DEFAULT 5000 CHECK (timeout_ms BETWEEN 100 AND 30000),
    status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('healthy', 'critical', 'unknown', 'disabled')),
    last_checked_at TEXT,
    response_time_ms INTEGER,
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 500),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(machine_id, check_type, port, path)
) STRICT;

CREATE INDEX checks_machine_id_idx ON checks(machine_id);
CREATE INDEX machines_status_idx ON machines(status);
