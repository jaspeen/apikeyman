-- name: GetApiKey :one
SELECT id,
  sec,
  KEY,
  sub,
  alg,
  exp,
  name
FROM apikey
WHERE id = $1;
-- name: GetApiKeyForVerify :one
SELECT id,
  sec,
  KEY,
  sub,
  alg
FROM apikey
WHERE id = $1
  AND (
    exp IS NULL
    OR exp > NOW()
  );
-- name: InsertApiKey :one
INSERT INTO apikey (sec, KEY, sub, alg, exp, name)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id;
-- name: SearchApiKeys :many
SELECT id,
  sec,
  KEY,
  sub,
  alg,
  exp,
  name
FROM apikey
WHERE sub = $1;