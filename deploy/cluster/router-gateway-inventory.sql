CREATE TABLE IF NOT EXISTS router_gateway_inventory (
    gateway smallint PRIMARY KEY CHECK (gateway BETWEEN 1 AND 3),
    collected_at bigint NOT NULL,
    peers jsonb NOT NULL CHECK (jsonb_typeof(peers) = 'array')
);
