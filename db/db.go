package db

import (
	"embed"

	"github.com/jaspeen/apikeyman/db/queries"
)

//go:embed migrations/*.sql
var fs embed.FS

var Queries = queries.New()
