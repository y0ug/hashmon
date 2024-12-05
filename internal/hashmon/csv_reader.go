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

	// No header
	// Read the header
	// header, err := reader.Read()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read CSV header: %v", err)
	// }
	//
	// // Validate header
	// if len(header) < 1 || header[0] != "sha256" {
	// 	return nil, fmt.Errorf("invalid CSV header, expected 'sha256'")
	// }
	//
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
		if len(record) < 1 {
			continue // Skip invalid records
		}

		hashRecord := models.HashRecord{
			FileName: record[0],
			SHA256:   record[1],
			BuildId:  record[2],
		}

		records = append(records, hashRecord)
	}

	return records, nil
}
