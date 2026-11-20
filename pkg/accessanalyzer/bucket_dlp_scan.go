package accessanalyzer

import (
	"context"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/dlp"
)

const (
	maxDLPScanFiles = 1000
	maxDLPScanBytes = 100 << 20
	dlpScanTimeout  = 2 * time.Minute
)

type dlpObject struct {
	Name    string
	Size    int64
	Updated time.Time
	Open    func(context.Context) (io.ReadCloser, error)
}

func scanDLPFiles(ctx context.Context, scanner *dlp.Scanner, bucket string, objects []dlpObject, previous *bucketDLPScan, started time.Time) *bucketDLPScan {
	ctx, cancel := context.WithTimeout(ctx, dlpScanTimeout)
	defer cancel()

	result := &bucketDLPScan{ResourceName: bucket}
	previousTime, cached := previous.scanCache()
	targets := dlpCandidates(scanner, objects, previousTime)
	checkpoint := started.Unix() - 1 // Keep writes in the same second eligible.
	processed := make(map[string]struct{}, min(len(targets), maxDLPScanFiles))
	var totalSize int64
	for i, object := range targets {
		if ctx.Err() != nil || i >= maxDLPScanFiles || object.Size > maxDLPScanBytes-totalSize {
			checkpoint = checkpointBefore(checkpoint, object.Updated)
			break
		}
		if file := scanDLPFile(ctx, scanner, object, cached[object.Name]); file != nil {
			result.addFile(*file)
		}
		processed[object.Name] = struct{}{}
		totalSize += object.Size
		if ctx.Err() != nil {
			checkpoint = checkpointBefore(checkpoint, object.Updated)
			break
		}
	}

	result.ScanTime = max(previousTime, checkpoint)
	result.ScanDuration = time.Since(started).String()
	result.retainPrevious(previous, objects, processed)
	return result
}

func dlpCandidates(scanner *dlp.Scanner, objects []dlpObject, previousTime int64) []dlpObject {
	cutoff := time.Unix(previousTime, 0)
	var candidates []dlpObject
	for _, object := range objects {
		if previousTime > 0 && !object.Updated.After(cutoff) {
			continue
		}
		if object.Size <= maxDLPScanBytes && scanner.CanScanFile(object.Name, object.Size) {
			candidates = append(candidates, object)
		}
	}
	slices.SortStableFunc(candidates, func(a, b dlpObject) int {
		return a.Updated.Compare(b.Updated)
	})
	return candidates
}

func checkpointBefore(checkpoint int64, updated time.Time) int64 {
	if updated.IsZero() {
		return 0
	}
	return min(checkpoint, updated.Unix()-1)
}

func scanDLPFile(ctx context.Context, scanner *dlp.Scanner, object dlpObject, cached bucketFileScan) *bucketFileScan {
	result := &bucketFileScan{Object: object.Name, Updated: object.Updated}
	reader, err := object.Open(ctx)
	if err != nil {
		result.FindingFile = dlp.NewFindingFile(dlp.ScanResponse{})
		return result
	}
	defer reader.Close()

	if cached.Complete && !object.Updated.IsZero() && object.Updated.Equal(cached.Updated) {
		return &cached
	}

	response, err := scanner.Scan(ctx, dlp.ScanRequest{FileName: object.Name, Reader: reader})
	if response != nil {
		result.FindingFile = dlp.NewFindingFile(*response)
		return result
	}
	if err != nil {
		result.FindingFile = dlp.NewFindingFile(dlp.ScanResponse{})
		return result
	}
	return nil
}

func (r *bucketDLPScan) scanCache() (int64, map[string]bucketFileScan) {
	if r == nil {
		return 0, nil
	}
	cache := make(map[string]bucketFileScan, len(r.SensitiveObjects)+len(r.unreportedFiles))
	for _, file := range r.SensitiveObjects {
		cache[file.Object] = file
	}
	for _, file := range r.unreportedFiles {
		cache[file.Object] = file
	}
	return r.ScanTime, cache
}

func (r *bucketDLPScan) retainPrevious(previous *bucketDLPScan, objects []dlpObject, processed map[string]struct{}) {
	if previous == nil {
		return
	}
	retained := make(map[string]struct{})
	legacyPaths := make(map[string]string)
	for _, object := range objects {
		if _, scanned := processed[object.Name]; scanned {
			continue
		}
		retained[object.Name] = struct{}{}
		if len(previous.previousFindings) > 0 {
			legacyPaths[path.Join(r.ResourceName, legacyDLPPath(object.Name))] = object.Name
		}
	}
	for _, file := range previous.SensitiveObjects {
		if _, keep := retained[file.Object]; keep {
			r.SensitiveObjects = append(r.SensitiveObjects, file)
		}
	}
	for _, file := range previous.unreportedFiles {
		if _, keep := retained[file.Object]; keep {
			r.unreportedFiles = append(r.unreportedFiles, file)
		}
	}
	if len(processed) == 0 && len(r.SensitiveObjects) == len(previous.SensitiveObjects) &&
		len(previous.unreportedFiles) == 0 && len(previous.previousFindings) == 0 {
		// Undetected files no longer have individual records to rebuild the summary.
		r.Sensitive = previous.Sensitive
		r.ContentType = previous.ContentType
	}
	r.mergeLegacyFindings(previous.previousFindings, func(filePath string) (string, bool) {
		name, ok := legacyPaths[filePath]
		return name, ok
	})
}

// Older directory scans recorded paths after normalizing characters for the local filesystem.
func legacyDLPPath(name string) string {
	parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
	for i, part := range parts {
		part = legacyDLPPathReplacer.Replace(part)
		if part == "" || part == "." {
			part = "unnamed"
		}
		parts[i] = part
	}
	return strings.Join(parts, "/")
}

var legacyDLPPathReplacer = strings.NewReplacer("..", "_", ":", "_", "*", "_", "?", "_", "<", "_", ">", "_", "|", "_", "\"", "_")
