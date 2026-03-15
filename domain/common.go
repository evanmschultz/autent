package domain

import (
	"maps"
	"slices"
	"strings"
)

// Status identifies whether a principal or client is active.
type Status string

const (
	// StatusActive allows a principal or client to participate in auth flows.
	StatusActive Status = "active"
	// StatusDisabled blocks a principal or client from participating in auth flows.
	StatusDisabled Status = "disabled"
)

// validStatuses stores supported status values.
var validStatuses = []Status{StatusActive, StatusDisabled}

// NormalizeStatus canonicalizes one status value.
func NormalizeStatus(status Status) Status {
	return Status(strings.TrimSpace(strings.ToLower(string(status))))
}

// IsValidStatus reports whether a status value is supported.
func IsValidStatus(status Status) bool {
	return slices.Contains(validStatuses, NormalizeStatus(status))
}

// copyMap returns a shallow copy of a string map.
func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	maps.Copy(out, in)
	return out
}
