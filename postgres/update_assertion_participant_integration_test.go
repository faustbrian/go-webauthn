//go:build integration

package postgres_test

import "testing"

func TestUpdateAssertionParticipationPostgres(t *testing.T) {
	testAssertionParticipationPostgres(t, false, true)
}
