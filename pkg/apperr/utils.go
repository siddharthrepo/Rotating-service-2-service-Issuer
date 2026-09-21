package apperr

import "errors"

func def(status int, code, msg string) *Error {
	return &Error{Code: code, Message: msg, Status: status}
}

func from(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// As extracts an *Error, or synthesises a generic internal one.
func As(err error) *Error {
	if e := from(err); e != nil {
		return e
	}
	return Internal.Wrap(err)
}

// HasCode reports whether err is an application error with the given code.
func HasCode(err error, code string) bool {
	e := from(err)
	return e != nil && e.Code == code
}
