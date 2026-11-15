package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"mandatnik/internal/platform"
	"mandatnik/internal/protocol"
)

// QueueItem is one durable report waiting for delivery.
type QueueItem struct {
	ReportID    string          `json:"report_id"`
	ScanSeq     int64           `json:"scan_seq"`
	CollectedAt string          `json:"collected_at"`
	QueuedAt    string          `json:"queued_at"`
	JobIDs      []string        `json:"job_ids,omitempty"`
	TaskItemIDs []string        `json:"task_item_ids,omitempty"`
	Report      protocol.Report `json:"report"`
}

// Queue stores exactly the two newest reports. Older files are evicted with an
// explicit result returned to the caller so job state can be updated.
type Queue struct {
	mu     sync.Mutex
	dir    string
	logger *Logger
	// nil means the production SYSTEM/Administrators ACL. Tests of queue
	// ordering inject their own file protection instead of requiring SYSTEM.
	protectFile func(string) error
}

func openQueue(logger *Logger) (*Queue, error) {
	dir := platform.AgentQueueDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Queue{dir: dir, logger: logger}, nil
}

// Add writes a report atomically and evicts the oldest reports above the limit.
func (q *Queue) Add(item QueueItem) ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if item.ReportID == "" {
		return nil, fmt.Errorf("queue item has no report_id")
	}
	if err := protocol.ValidateReport(&item.Report); err != nil {
		return nil, fmt.Errorf("queue report invalid: %s", err.Message)
	}
	if item.QueuedAt == "" {
		item.QueuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(q.dir, "report-"+item.ReportID+".json")
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return nil, err
	}
	protect := q.protectFile
	if protect == nil {
		protect = securePath
	}
	if err := protect(path); err != nil {
		return nil, err
	}
	return q.trimLocked()
}

func (q *Queue) Remove(reportID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	err := os.Remove(filepath.Join(q.dir, "report-"+reportID+".json"))
	_ = os.Remove(q.evictedPath(reportID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (q *Queue) reportPath(reportID string) string {
	return filepath.Join(q.dir, "report-"+reportID+".json")
}

func (q *Queue) evictedPath(reportID string) string {
	return filepath.Join(q.dir, "evicted-"+reportID+".json")
}

func (q *Queue) Contains(reportID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, err := os.Stat(q.reportPath(reportID))
	return err == nil
}

func (q *Queue) Evicted(reportID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, err := os.Stat(q.evictedPath(reportID))
	return err == nil
}

// Items returns queued reports oldest-first. Corrupt files are archived and
// skipped rather than blocking delivery of valid reports.
func (q *Queue) Items() ([]QueueItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var items []QueueItem
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "report-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(q.dir, entry.Name())
		item, err := readQueueItem(path)
		if err != nil {
			q.archiveCorrupt(path, err)
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].QueuedAt == items[j].QueuedAt {
			return items[i].ReportID < items[j].ReportID
		}
		return items[i].QueuedAt < items[j].QueuedAt
	})
	return items, nil
}

func (q *Queue) Count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "report-") && strings.HasSuffix(entry.Name(), ".json") {
			count++
		}
	}
	return count
}

func (q *Queue) trim() ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.trimLocked()
}

func (q *Queue) trimLocked() ([]string, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	type queuedFile struct {
		name     string
		queuedAt string
		reportID string
	}
	var files []queuedFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "report-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(q.dir, entry.Name())
		item, err := readQueueItem(path)
		if err != nil {
			q.archiveCorrupt(path, err)
			continue
		}
		files = append(files, queuedFile{name: entry.Name(), queuedAt: item.QueuedAt, reportID: item.ReportID})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].queuedAt == files[j].queuedAt {
			return files[i].reportID < files[j].reportID
		}
		return files[i].queuedAt < files[j].queuedAt
	})
	var evicted []string
	for len(files) > protocol.QueueMaxReports {
		oldest := files[0]
		if err := writeFileAtomic(q.evictedPath(oldest.reportID), []byte("evicted\n"), 0o600); err != nil {
			return evicted, err
		}
		if err := os.Remove(filepath.Join(q.dir, oldest.name)); err != nil {
			return evicted, err
		}
		evicted = append(evicted, oldest.reportID)
		if q.logger != nil {
			q.logger.Logf("report queue evicted oldest report %s", oldest.reportID)
		}
		files = files[1:]
	}
	return evicted, nil
}

func readQueueItem(path string) (QueueItem, error) {
	var item QueueItem
	raw, err := os.ReadFile(path)
	if err != nil {
		return item, err
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return item, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&item); err != nil {
		return item, err
	}
	if item.ReportID == "" || item.Report.ReportID != item.ReportID {
		return item, fmt.Errorf("queue report_id mismatch")
	}
	if err := protocol.ValidateReport(&item.Report); err != nil {
		return item, fmt.Errorf("queue report invalid: %s", err.Message)
	}
	return item, nil
}

func (q *Queue) archiveCorrupt(path string, cause error) {
	target := filepath.Join(q.dir, "corrupt-"+filepath.Base(path)+"."+time.Now().UTC().Format("20060102T150405"))
	if err := os.Rename(path, target); err != nil {
		if q.logger != nil {
			q.logger.Logf("could not archive corrupt queue item %s: %v", path, err)
		}
		return
	}
	if q.logger != nil {
		q.logger.Logf("archived corrupt queue item %s: %v", filepath.Base(path), cause)
	}
}
