package database

import "fmt"

// generateProviderKey creates a composite key using provider and userID.
func generateProviderKey(provider, userID string) []byte {
	return []byte(fmt.Sprintf("%s:%s", provider, userID))
}
