SET NOCOUNT ON;

PRINT '== machines and registrations';
SELECT m.display_name, m.machine_id, r.registration_id, r.uuid, r.hostname, r.state,
       r.previous_registration_id, r.replaced_by_registration_id
FROM dbo.machines m
JOIN dbo.registrations r ON r.machine_id=m.machine_id
ORDER BY m.display_name, r.registration_id;

PRINT '== machine users';
SELECT m.display_name, mu.sid, mu.name, mu.loaded, mu.present
FROM dbo.machines m JOIN dbo.machine_users mu ON mu.machine_id=m.machine_id
ORDER BY m.display_name, mu.sid;

PRINT '== CSP and licenses';
SELECT m.display_name, c.product_version, c.core_version, c.license_kind, c.license_kind_raw,
       c.license_kind_source, c.license_state, c.valid_to_raw, c.time_basis, c.term_kind,
       c.is_trial, c.complete
FROM dbo.machines m JOIN dbo.csp_states c ON c.machine_id=m.machine_id
ORDER BY m.display_name;

PRINT '== observations per certificate and machine (history incl. removed fixtures; same DER across machines)';
SELECT o.certificate_sha256, COUNT(DISTINCT o.machine_id) AS machines, COUNT(*) AS observation_rows,
       SUM(CASE WHEN o.active=1 THEN 1 ELSE 0 END) AS active_rows
FROM dbo.certificate_observations o
GROUP BY o.certificate_sha256
ORDER BY machines DESC, o.certificate_sha256;

PRINT '== active folder observations';
SELECT m.display_name, o.file_path, o.certificate_sha256, o.active
FROM dbo.certificate_observations o JOIN dbo.machines m ON m.machine_id=o.machine_id
WHERE o.source_type='folder'
ORDER BY m.display_name, o.file_path;

PRINT '== reports';
SELECT m.display_name, r.report_id, r.scan_seq, r.status, r.applied, r.applied_sources,
       r.collected_at, r.received_at
FROM dbo.reports r JOIN dbo.machines m ON m.machine_id=r.machine_id
ORDER BY m.display_name, r.scan_seq;

PRINT '== jobs';
SELECT m.display_name, j.job_id, j.state, j.report_id, j.created_at, j.completed_at
FROM dbo.jobs j JOIN dbo.machines m ON m.machine_id=j.machine_id
ORDER BY m.display_name, j.created_at;

PRINT '== hostname reservations';
SELECT hostname_norm, display_name, owner_registration_id, owner_machine_id
FROM dbo.hostnames ORDER BY hostname_norm;

PRINT '== events by kind';
SELECT kind, severity, COUNT(*) AS events
FROM dbo.events GROUP BY kind, severity ORDER BY kind, severity;

PRINT '== test fixture certificate fields';
SELECT c.sha256, c.serial_hex, c.subject, c.not_before, c.not_after, c.issuer
FROM dbo.certificates c
WHERE c.sha256 IN (
 '686e89cb4235914d9e48c68fc1dca73b248e349493df781c3b8de3510ac6868d',
 '88f4d4178d3304170c59cf9a17dc2f11447b3ea1dee52a081dd5d10a32f010a6',
 'dc7667ab2db38b2e2150753f1dd686b74ea4922807706c9e65c79b842a090de9',
 '6a9c17b4934aaea8214360f75fda8b97542d5b194558f3fc8c557451a70270e1',
 'a3a1624b9caa518b1ebebf003fcfb6d125bb1d3ce5728957e9aa2cd6a430b2c8',
 '96b830dff36475ab9c9d8bcc281b9f13ca4d8746a33766b63d533fe19a88dcaf',
 '9b8113505011b5910e0e29dce12f4486c2e99bd0eec0d63cf8be1c382e4ffe83',
 '5d2deccffd076c01818df6c9144897da90eabf5d278697ce051aac54f04c0080'
)
ORDER BY c.serial_hex;
