CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE
        CHECK (length(name) BETWEEN 1 AND 100),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE machine_groups (
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, group_id)
) STRICT;

CREATE TABLE discovery_jobs (
    id INTEGER PRIMARY KEY,
    target_cidr TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    total_addresses INTEGER NOT NULL CHECK (total_addresses BETWEEN 1 AND 256),
    processed_addresses INTEGER NOT NULL DEFAULT 0
        CHECK (processed_addresses BETWEEN 0 AND total_addresses),
    responsive_hosts INTEGER NOT NULL DEFAULT 0
        CHECK (responsive_hosts BETWEEN 0 AND total_addresses),
    error TEXT CHECK (error IS NULL OR length(error) <= 500),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT
) STRICT;

CREATE TABLE discovered_devices (
    id INTEGER PRIMARY KEY,
    job_id INTEGER NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    detected_port INTEGER CHECK (detected_port IS NULL OR detected_port BETWEEN 1 AND 65535),
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'imported', 'ignored')),
    machine_id INTEGER REFERENCES machines(id) ON DELETE SET NULL,
    discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (job_id, address)
) STRICT;

CREATE INDEX machine_groups_group_id_idx ON machine_groups(group_id);
CREATE INDEX discovery_jobs_created_at_idx ON discovery_jobs(created_at DESC);
CREATE INDEX discovered_devices_job_id_idx ON discovered_devices(job_id);
