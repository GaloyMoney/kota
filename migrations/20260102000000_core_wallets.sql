CREATE TABLE core_wallets (
  id UUID PRIMARY KEY,
  descriptor_fingerprint VARCHAR NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE core_wallet_events (
  id UUID NOT NULL REFERENCES core_wallets(id),
  sequence INT NOT NULL,
  event_type VARCHAR NOT NULL,
  event JSONB NOT NULL,
  context JSONB DEFAULT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  UNIQUE(id, sequence)
);
