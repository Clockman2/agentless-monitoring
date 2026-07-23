CREATE TABLE discovered_device_ports (
    device_id INTEGER NOT NULL REFERENCES discovered_devices(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    PRIMARY KEY (device_id, port)
) STRICT;

INSERT INTO discovered_device_ports (device_id, port)
SELECT id, detected_port
FROM discovered_devices
WHERE detected_port IS NOT NULL;
