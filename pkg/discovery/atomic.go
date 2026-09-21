package discovery

import (
	"fmt"
	"os"
	"time"
)

// writeFileAtomic writes data to a temporary file in the same directory as path,
// then atomically renames it to path to prevent corrupted or truncated files on crashes.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}
