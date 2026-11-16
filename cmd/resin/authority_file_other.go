//go:build !linux

package main

import "errors"

func verifyPrivateAuthorityPath(string) error {
	return errors.New("candidate authority requires Linux file identity verification")
}
