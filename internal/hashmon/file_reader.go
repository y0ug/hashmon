package hashmon

import (
	"bufio"
	"fmt"
	"os"

	"github.com/y0ug/hashmon/internal/database/models"
)

// ReadTxtFile reads a TXT file and returns a slice of HashRecords
func ReadTxtFile(filePath string) ([]models.HashRecord, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var records []models.HashRecord

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Assuming each line contains only the hash. If comments are needed, adjust accordingly.
		hash := line
		record := models.HashRecord{Hash: hash}

		// Validate the hash
		if err := record.ValidateHash(); err != nil {
			// Log the error and skip the record
			fmt.Printf("Invalid hash format for line '%s': %v\n", line, err)
			continue
		}

		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	return records, nil
}
