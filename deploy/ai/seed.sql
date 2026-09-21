-- Seed data for the /ai vertical-slice demo database (docker-compose.ai.yml).
-- One small table so "discover -> read -> plan a write -> approve -> receipt"
-- has something real to show on a fresh checkout.
CREATE TABLE IF NOT EXISTS demo_customers (
    id serial PRIMARY KEY,
    name text NOT NULL,
    plan text NOT NULL
);

INSERT INTO demo_customers (name, plan)
SELECT 'Acme Robotics', 'cell'
WHERE NOT EXISTS (SELECT 1 FROM demo_customers);
