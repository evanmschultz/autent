package domain

import (
	"strings"
	"time"
)

// ClientInput carries fields used to construct a client.
type ClientInput struct {
	ID          string
	DisplayName string
	Type        string
	Status      Status
	Metadata    map[string]string
}

// Client stores a software client or integration surface record.
type Client struct {
	ID          string
	DisplayName string
	Type        string
	Status      Status
	Metadata    map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewClient validates and constructs a client record.
func NewClient(in ClientInput, now time.Time) (Client, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return Client{}, ErrInvalidID
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		return Client{}, ErrInvalidDisplayName
	}
	clientType := strings.TrimSpace(strings.ToLower(in.Type))
	if clientType == "" {
		return Client{}, ErrInvalidClientType
	}
	status := NormalizeStatus(in.Status)
	if status == "" {
		status = StatusActive
	}
	if !IsValidStatus(status) {
		return Client{}, ErrInvalidStatus
	}

	ts := now.UTC()
	return Client{
		ID:          id,
		DisplayName: displayName,
		Type:        clientType,
		Status:      status,
		Metadata:    copyMap(in.Metadata),
		CreatedAt:   ts,
		UpdatedAt:   ts,
	}, nil
}

// IsActive reports whether the client is active.
func (c Client) IsActive() bool {
	return NormalizeStatus(c.Status) == StatusActive
}

// UpdateStatus changes the client status and refreshes the updated timestamp.
func (c *Client) UpdateStatus(status Status, now time.Time) error {
	if c == nil {
		return ErrInvalidStatus
	}
	normalized := NormalizeStatus(status)
	if !IsValidStatus(normalized) {
		return ErrInvalidStatus
	}
	c.Status = normalized
	c.UpdatedAt = now.UTC()
	return nil
}
