CREATE INDEX audit_failed_login_id_idx
ON audit_events(id DESC)
WHERE action = 'user.login' AND outcome = 'failure';
