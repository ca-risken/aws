package accessanalyzer

import (
	"cmp"
	"context"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/dlp"
	"golang.org/x/sync/semaphore"
)

const (
	maxDLPScanFiles = 1000
	maxDLPScanBytes = 100 << 20
	dlpScanTimeout  = 2 * time.Minute
)

// Bound file-body memory across concurrent bucket scans in this worker.
var dlpFileSlot = semaphore.NewWeighted(1)

type dlpObject struct {
	Name    string
	Size    int64
	Updated time.Time
	Open    func(context.Context) (io.ReadCloser, error)
}

type dlpObjectLister func(context.Context, func(dlpObject)) error

type dlpScanCursor struct {
	Updated time.Time `json:"updated"`
	Object  string    `json:"object"`
}

func (c dlpScanCursor) compareObject(object dlpObject) int {
	if order := c.Updated.Compare(object.Updated); order != 0 {
		return order
	}
	return cmp.Compare(c.Object, object.Name)
}

type dlpObjectSelection struct {
	targets     []dlpObject
	seen        map[string]struct{}
	legacyPaths map[string]string
	pending     *dlpScanCursor
}

func scanDLPFiles(ctx context.Context, scanner *dlp.Scanner, bucket string, listObjects dlpObjectLister, previous *bucketDLPScan, started time.Time) (*bucketDLPScan, error) {
	ctx, cancel := context.WithTimeout(ctx, dlpScanTimeout)
	defer cancel()

	previousTime, cached := previous.scanCache()
	selection, err := selectDLPObjects(ctx, scanner, bucket, listObjects, previous, cached)
	if err != nil {
		return previous, err
	}

	result := &bucketDLPScan{ResourceName: bucket}
	processed := make(map[string]struct{}, len(selection.targets))
	var totalSize int64
	for _, object := range selection.targets {
		if ctx.Err() != nil || object.Size > maxDLPScanBytes-totalSize {
			selection.postpone(object)
			break
		}
		file := scanDLPFile(ctx, scanner, object, cached[object.Name])
		if ctx.Err() != nil {
			selection.postpone(object)
			break
		}
		if file != nil {
			result.addFile(*file)
		}
		processed[object.Name] = struct{}{}
		totalSize += object.Size
	}

	checkpoint := started.Unix() - 1 // Keep writes in the same second eligible.
	if pending := selection.pending; pending != nil {
		checkpoint = checkpointBefore(checkpoint, pending.Updated)
		if !pending.Updated.IsZero() && pending.Updated.Unix() < started.Unix() {
			// The object name lets a batch resume amid objects with the same timestamp.
			result.ScanCursor = pending
		}
	}
	result.ScanTime = max(previousTime, checkpoint)
	result.ScanDuration = time.Since(started).String()
	result.retainPrevious(previous, selection, processed)
	return result, nil
}

func selectDLPObjects(ctx context.Context, scanner *dlp.Scanner, bucket string, listObjects dlpObjectLister, previous *bucketDLPScan, cached map[string]bucketFileScan) (dlpObjectSelection, error) {
	selection := dlpObjectSelection{
		seen:        make(map[string]struct{}),
		legacyPaths: make(map[string]string),
	}
	var cutoff time.Time
	var cursor *dlpScanCursor
	if previous != nil {
		cursor = previous.ScanCursor
		if previous.ScanTime > 0 {
			cutoff = time.Unix(previous.ScanTime, 0)
		}
		for _, finding := range previous.previousFindings {
			selection.legacyPaths[finding.FilePath] = ""
		}
	}

	err := listObjects(ctx, func(object dlpObject) {
		if _, ok := cached[object.Name]; ok {
			selection.seen[object.Name] = struct{}{}
		}
		if len(selection.legacyPaths) > 0 {
			key := path.Join(bucket, legacyDLPPath(object.Name))
			if _, ok := selection.legacyPaths[key]; ok {
				selection.legacyPaths[key] = object.Name
			}
		}
		if !cutoff.IsZero() && !object.Updated.After(cutoff) {
			return
		}
		if cursor != nil && cursor.compareObject(object) > 0 {
			return
		}
		if object.Size > maxDLPScanBytes || !scanner.CanScanFile(object.Name, object.Size) {
			return
		}
		selection.targets = append(selection.targets, object)
		if len(selection.targets) == 2*maxDLPScanFiles {
			selection.keepOldestTargets()
		}
	})
	if err != nil {
		return dlpObjectSelection{}, err
	}
	if err := ctx.Err(); err != nil {
		return dlpObjectSelection{}, err
	}
	selection.keepOldestTargets()
	return selection, nil
}

func (s *dlpObjectSelection) keepOldestTargets() {
	slices.SortFunc(s.targets, func(a, b dlpObject) int {
		return (dlpScanCursor{Updated: a.Updated, Object: a.Name}).compareObject(b)
	})
	if len(s.targets) <= maxDLPScanFiles {
		return
	}
	s.postpone(s.targets[maxDLPScanFiles])
	clear(s.targets[maxDLPScanFiles:])
	s.targets = s.targets[:maxDLPScanFiles]
}

func (s *dlpObjectSelection) postpone(object dlpObject) {
	if s.pending == nil || s.pending.compareObject(object) > 0 {
		s.pending = &dlpScanCursor{Updated: object.Updated, Object: object.Name}
	}
}

func checkpointBefore(checkpoint int64, updated time.Time) int64 {
	if updated.IsZero() {
		return 0
	}
	return min(checkpoint, updated.Unix()-1)
}

func scanDLPFile(ctx context.Context, scanner *dlp.Scanner, object dlpObject, cached bucketFileScan) *bucketFileScan {
	if cached.Complete && !object.Updated.IsZero() && object.Updated.Equal(cached.Updated) {
		return &cached
	}
	if err := dlpFileSlot.Acquire(ctx, 1); err != nil {
		return nil
	}
	defer dlpFileSlot.Release(1)

	result := &bucketFileScan{Object: object.Name, Updated: object.Updated}
	reader, err := object.Open(ctx)
	if err != nil {
		result.FindingFile = dlp.NewFindingFile(dlp.ScanResponse{})
		return result
	}
	defer reader.Close()

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

func (r *bucketDLPScan) retainPrevious(previous *bucketDLPScan, selection dlpObjectSelection, processed map[string]struct{}) {
	if previous == nil {
		return
	}
	for name := range processed {
		delete(selection.seen, name)
	}
	for _, file := range previous.SensitiveObjects {
		if _, keep := selection.seen[file.Object]; keep {
			r.SensitiveObjects = append(r.SensitiveObjects, file)
		}
	}
	for _, file := range previous.unreportedFiles {
		if _, keep := selection.seen[file.Object]; keep {
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
		name := selection.legacyPaths[filePath]
		_, scanned := processed[name]
		return name, name != "" && !scanned
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
