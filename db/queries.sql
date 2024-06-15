-- name: GetApiKey :one
SELECT id,
  sec,
  KEY,
  sub,
  alg,
  exp,
  name,
  extra
FROM apikey
WHERE id = $1;
-- name: GetApiKeyForVerify :one
SELECT id,
  sec,
  KEY,
  sub,
  alg,
  extra
FROM apikey
WHERE id = $1
  AND (
    exp IS NULL
    OR exp > NOW()
  );
-- name: InsertApiKey :one
INSERT INTO apikey (sec, KEY, sub, alg, exp, name, extra)
VALUES ($1, $2, $3, $4, $5, $6, $7)
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
WHERE (
    sub = $1
    OR $1 IS NULL
  );