-- A "legacy" system: it only understands database users, not OAuth tokens. Agents reach it
-- with short-lived users that Vault creates per request (database secrets engine).
CREATE TABLE assets (
  system              text PRIMARY KEY,
  owner               text NOT NULL,
  cost_center         text NOT NULL,
  criticality         text NOT NULL,
  data_classification text NOT NULL,
  last_dr_test        date
);
INSERT INTO assets VALUES
  ('payments-api', 'payments-team',  'CC-4410', 'mission-critical', 'PCI',          '2026-06-12'),
  ('erp-db',       'data-platform',  'CC-2001', 'business-critical', 'confidential', '2026-03-30'),
  ('hr-portal',    'people-tech',    'CC-3150', 'important',        'PII',          '2025-11-02');

-- Vault's management account: may create/drop the short-lived users, nothing else.
CREATE ROLE vaultadmin WITH LOGIN CREATEROLE PASSWORD 'vaultadmin-secret';
GRANT SELECT ON assets TO vaultadmin WITH GRANT OPTION;
