// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package queries

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
)

type AlgType string

const (
	AlgTypeRS256  AlgType = "RS256"
	AlgTypeRS512  AlgType = "RS512"
	AlgTypeES256  AlgType = "ES256"
	AlgTypeES256K AlgType = "ES256K"
	AlgTypeEdDSA  AlgType = "EdDSA"
)

func (e *AlgType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = AlgType(s)
	case string:
		*e = AlgType(s)
	default:
		return fmt.Errorf("unsupported scan type for AlgType: %T", src)
	}
	return nil
}

type NullAlgType struct {
	AlgType AlgType `json:"alg_type"`
	Valid   bool    `json:"valid"` // Valid is true if AlgType is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullAlgType) Scan(value interface{}) error {
	if value == nil {
		ns.AlgType, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.AlgType.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullAlgType) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.AlgType), nil
}

type Apikey struct {
	ID   int64          `json:"id"`
	Sec  []byte         `json:"sec"`
	Key  []byte         `json:"key"`
	Sub  sql.NullString `json:"sub"`
	Alg  NullAlgType    `json:"alg"`
	Exp  sql.NullTime   `json:"exp"`
	Name sql.NullString `json:"name"`
}
