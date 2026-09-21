package structs

import (
	"database/sql"
	"fmt"
	"net"
)

func jsonBytes(src any, field string) ([]byte, error) {
	switch v := src.(type) {
	case nil:
		return nil, nil
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("scan %s: unsupported type %T", field, src)
	}
}

// NewNullString saves callers repeating the Valid dance for optional columns.
func NewNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// IPBytes normalises a remote address to the 4 or 16 bytes the VARBINARY audit
// column expects.
func IPBytes(remote string) []byte {
	ip := net.ParseIP(remote)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}
