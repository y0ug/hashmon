package main

import (
	"path/filepath"
	"strings"

	"github.com/y0ug/hashmon/models"
)

// ReadRecords reads hash records from a CSV or TXT file based on the file extension.
func ReadRecords(filePath string) ([]models.HashRecord, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".csv":
		return ReadCSV(filePath)
	default:
		return ReadTxtFile(filePath)
	}
}
