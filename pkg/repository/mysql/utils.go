package mysql

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
)

func isDuplicate(err error, index string) bool {
	var me *mysql.MySQLError
	if !errors.As(err, &me) || me.Number != constants.MySQLErrDupEntry {
		return false
	}

	return index == "" || strings.Contains(me.Message, index)
}

func isCheckViolation(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == constants.MySQLErrCheckConstraint
}

func noRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func requireAffected(res sql.Result, notFound *apperr.Error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return notFound
	}
	return nil
}

func lastInsertID(res sql.Result, what string) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s last insert id: %w", what, err)
	}
	return uint64(id), nil
}

func applyPaging(limit, offset int) (int, int) {
	if limit <= 0 || limit > constants.MaxPageLimit {
		limit = constants.DefaultPageLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
