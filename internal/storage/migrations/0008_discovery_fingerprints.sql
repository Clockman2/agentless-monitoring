CREATE TABLE discovered_device_fingerprints (
    device_id INTEGER NOT NULL REFERENCES discovered_devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('ssh-host-key', 'tls-certificate')),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 160),
    PRIMARY KEY (device_id, kind, value)
) STRICT;

CREATE INDEX discovered_device_fingerprints_lookup_idx
    ON discovered_device_fingerprints(kind, value);
