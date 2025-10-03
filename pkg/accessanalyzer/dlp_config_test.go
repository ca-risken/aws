package accessanalyzer

import (
	"testing"
)

func TestDLPRule_IsApplicableToFile(t *testing.T) {
	minSize1KB := 1
	minSize10KB := 10

	tests := []struct {
		name          string
		rule          DLPRule
		fileName      string
		fileSizeBytes int64
		want          bool
	}{
		{
			name: "No filters - always applicable",
			rule: DLPRule{
				Name:        "Test Rule",
				FileFilters: nil,
			},
			fileName:      "test.csv",
			fileSizeBytes: 1024,
			want:          true,
		},
		{
			name: "Include extensions - match .csv",
			rule: DLPRule{
				Name: "CSV Only Rule",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv", ".tsv"},
				},
			},
			fileName:      "data.csv",
			fileSizeBytes: 1024,
			want:          true,
		},
		{
			name: "Include extensions - no match .txt",
			rule: DLPRule{
				Name: "CSV Only Rule",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv", ".tsv"},
				},
			},
			fileName:      "data.txt",
			fileSizeBytes: 1024,
			want:          false,
		},
		{
			name: "Exclude file name - match backup pattern",
			rule: DLPRule{
				Name: "No Backup Files",
				FileFilters: &FileFilters{
					ExcludeFileName: []string{"*_backup*", "*_temp*"},
				},
			},
			fileName:      "data_backup.csv",
			fileSizeBytes: 1024,
			want:          false,
		},
		{
			name: "Exclude file name - no match",
			rule: DLPRule{
				Name: "No Backup Files",
				FileFilters: &FileFilters{
					ExcludeFileName: []string{"*_backup*", "*_temp*"},
				},
			},
			fileName:      "data.csv",
			fileSizeBytes: 1024,
			want:          true,
		},
		{
			name: "Min size - file too small",
			rule: DLPRule{
				Name: "Min 10KB Rule",
				FileFilters: &FileFilters{
					MinSizeKB: &minSize10KB,
				},
			},
			fileName:      "small.csv",
			fileSizeBytes: 5 * 1024, // 5KB
			want:          false,
		},
		{
			name: "Min size - file large enough",
			rule: DLPRule{
				Name: "Min 10KB Rule",
				FileFilters: &FileFilters{
					MinSizeKB: &minSize10KB,
				},
			},
			fileName:      "large.csv",
			fileSizeBytes: 15 * 1024, // 15KB
			want:          true,
		},
		{
			name: "Combined filters - all match",
			rule: DLPRule{
				Name: "Client ID Header",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv", ".tsv"},
					ExcludeFileName:   []string{"*_backup*", "*_temp*"},
					MinSizeKB:         &minSize1KB,
				},
			},
			fileName:      "client_data.csv",
			fileSizeBytes: 2 * 1024, // 2KB
			want:          true,
		},
		{
			name: "Combined filters - extension mismatch",
			rule: DLPRule{
				Name: "Client ID Header",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv", ".tsv"},
					ExcludeFileName:   []string{"*_backup*", "*_temp*"},
					MinSizeKB:         &minSize1KB,
				},
			},
			fileName:      "client_data.json",
			fileSizeBytes: 2 * 1024,
			want:          false,
		},
		{
			name: "Combined filters - excluded file name",
			rule: DLPRule{
				Name: "Client ID Header",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv", ".tsv"},
					ExcludeFileName:   []string{"*_backup*", "*_temp*"},
					MinSizeKB:         &minSize1KB,
				},
			},
			fileName:      "client_data_backup.csv",
			fileSizeBytes: 2 * 1024,
			want:          false,
		},
		{
			name: "Combined filters - too small",
			rule: DLPRule{
				Name: "Client ID Header",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv", ".tsv"},
					ExcludeFileName:   []string{"*_backup*", "*_temp*"},
					MinSizeKB:         &minSize1KB,
				},
			},
			fileName:      "client_data.csv",
			fileSizeBytes: 512, // 0.5KB
			want:          false,
		},
		{
			name: "Path with directories",
			rule: DLPRule{
				Name: "CSV Rule",
				FileFilters: &FileFilters{
					IncludeExtensions: []string{".csv"},
					ExcludeFileName:   []string{"*_temp*"},
				},
			},
			fileName:      "s3://bucket/path/to/data.csv",
			fileSizeBytes: 1024,
			want:          true,
		},
		{
			name: "Exclude pattern with path",
			rule: DLPRule{
				Name: "No Temp Files",
				FileFilters: &FileFilters{
					ExcludeFileName: []string{"*_temp*"},
				},
			},
			fileName:      "s3://bucket/path/to/data_temp.csv",
			fileSizeBytes: 1024,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.IsApplicableToFile(tt.fileName, tt.fileSizeBytes)
			if got != tt.want {
				t.Errorf("IsApplicableToFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
