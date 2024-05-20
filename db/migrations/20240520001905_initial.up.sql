CREATE TYPE alg_type AS ENUM ('RS256', 'RS512', 'ES256', 'ES256K', 'EdDSA');
CREATE TABLE apikey (
  /* api key ID */
  id BIGSERIAL PRIMARY KEY,
  /* hash of the secret */
  sec bytea NOT NULL,
  /* optional encryption public key if alg is not NULL */
  KEY bytea,
  /* optional user id, subject; if null id will be returned as subject */
  sub text,
  /* optional encryption algorithm type */
  alg alg_type,
  /* optional expiration date */
  exp timestamptz,
  /* optional label */
  name text
);
CREATE INDEX idx_apikey_id_exp ON apikey (id, exp);
-- for list of apikeys
CREATE INDEX idx_apikey_sub ON apikey (sub);