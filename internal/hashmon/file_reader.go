package hashmon

import (
	"bufio"
	"fmt"
	"os"

	"github.com/y0ug/hashmon/internal/database/models"
)

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
		record := models.HashRecord{SHA256: line}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	return records, nil
}
