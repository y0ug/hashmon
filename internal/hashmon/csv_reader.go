package hashmon

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/y0ug/hashmon/internal/database/models"
)

// ReadCSV reads the CSV file and returns a slice of HashRecords
func ReadCSV(filePath string) ([]models.HashRecord, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	// Expected header: comment,hash
	// header, err := reader.Read()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read CSV header: %v", err)
	// }
	//
	// if len(header) < 2 || strings.ToLower(header[0]) != "comment" || strings.ToLower(header[1]) != "hash" {
	// 	return nil, fmt.Errorf("invalid CSV header, expected 'comment,hash'")
	// }

	var records []models.HashRecord

	// Read the rest of the records
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV: %v", err)
		}
		if len(record) < 2 {
			continue // Skip invalid records
		}

		hashRecord := models.HashRecord{
			Comment: record[0],
			Hash:    record[1],
			// LastCheckAt will be set to zero value; can be updated later
		}

		// Validate the hash
		if err := hashRecord.ValidateHash(); err != nil {
			// Log the error and skip the record
			fmt.Printf("Invalid hash format for record %+v: %v\n", hashRecord, err)
			continue
		}

		records = append(records, hashRecord)
	}

	return records, nil
}
