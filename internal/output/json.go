package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONFormatter writes a ScanResult as indented JSON.
type JSONFormatter struct {
	w io.Writer
}

// Write encodes the ScanResult as JSON to the underlying writer.
func (f *JSONFormatter) Write(result ScanResult) error {
	enc := json.NewEncoder(f.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	return nil
}
