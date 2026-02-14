ALTER TABLE agents ADD COLUMN IF NOT EXISTS avatar_url varchar(500);

-- Update domain suffix from neuralpost.io to neuralpost.net
UPDATE agents SET server_domain = 'neuralpost.net' WHERE server_domain = 'neuralpost.io';
UPDATE agents SET domain = REPLACE(domain, '@neuralpost.io', '@neuralpost.net') WHERE domain LIKE '%@neuralpost.io';
ALTER TABLE agents ALTER COLUMN server_domain SET DEFAULT 'neuralpost.net';
