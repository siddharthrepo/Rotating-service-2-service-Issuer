package cache

import (
	"fmt"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
)

// CurrentTokenKey is the key a grant's plaintext token is cached under.
func CurrentTokenKey(grantID uint64) string {
	return fmt.Sprintf("%s%d", constants.RedisKeyCurrentToken, grantID)
}

// TokenKey is the key a validated token record is cached under, by hash.
func TokenKey(hash string) string {
	return constants.RedisKeyToken + hash
}

// NegativeKey marks a hash known not to exist, so spraying garbage tokens cannot
// turn into a free query per request against MySQL.
func NegativeKey(hash string) string {
	return constants.RedisKeyNegative + hash
}
