CREATE TABLE core_psbt_sessions (
  id UUID PRIMARY KEY,
  wallet_id UUID NOT NULL,
  status VARCHAR NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE core_psbt_session_events (
  id UUID NOT NULL REFERENCES core_psbt_sessions(id),
  sequence INT NOT NULL,
  event_type VARCHAR NOT NULL,
  event JSONB NOT NULL,
  context JSONB DEFAULT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  UNIQUE(id, sequence)
);
