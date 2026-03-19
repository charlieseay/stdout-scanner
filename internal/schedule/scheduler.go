package schedule

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Schedule represents a user-configured scan schedule.
type Schedule struct {
	Interval string `json:"interval"` // "hourly", "daily", "weekly", or cron expression
	Hour     int    `json:"hour"`     // hour of day (0-23) for daily/weekly
	Minute   int    `json:"minute"`   // minute (0-59)
	Weekday  int    `json:"weekday"`  // day of week (0=Sun) for weekly
	Enabled  bool   `json:"enabled"`
}

// DefaultSchedule returns a daily 3:00 AM schedule.
func DefaultSchedule() Schedule {
	return Schedule{
		Interval: "daily",
		Hour:     3,
		Minute:   0,
		Enabled:  true,
	}
}

// ParseSchedule parses a schedule string from CLI flags.
// Accepts: "hourly", "daily", "weekly", "daily@03:00", "weekly@sun@03:00",
// or a cron expression like "0 3 * * *".
func ParseSchedule(s string) (Schedule, error) {
	sched := DefaultSchedule()

	switch {
	case s == "hourly":
		sched.Interval = "hourly"
	case s == "daily":
		sched.Interval = "daily"
	case s == "weekly":
		sched.Interval = "weekly"
	case strings.HasPrefix(s, "daily@"):
		sched.Interval = "daily"
		h, m, err := parseTime(strings.TrimPrefix(s, "daily@"))
		if err != nil {
			return sched, err
		}
		sched.Hour = h
		sched.Minute = m
	case strings.HasPrefix(s, "weekly@"):
		sched.Interval = "weekly"
		parts := strings.SplitN(strings.TrimPrefix(s, "weekly@"), "@", 2)
		sched.Weekday = parseDayOfWeek(parts[0])
		if len(parts) == 2 {
			h, m, err := parseTime(parts[1])
			if err != nil {
				return sched, err
			}
			sched.Hour = h
			sched.Minute = m
		}
	default:
		// Treat as cron expression
		sched.Interval = s
	}

	return sched, nil
}

// Run starts the scheduler loop. It runs the provided scanFunc on schedule.
// The schedule can be overridden by the StdOut API if a URL and token are
// configured — this lets users change the schedule from the web UI.
func Run(ctx context.Context, sched Schedule, stdoutURL, stdoutToken string, scanFunc func()) {
	fmt.Fprintf(os.Stderr, "Scheduler started: %s\n", describeSchedule(sched))

	for {
		// Check for updated schedule from StdOut API
		if stdoutURL != "" && stdoutToken != "" {
			if remote, err := fetchRemoteSchedule(stdoutURL, stdoutToken); err == nil {
				if remote.Interval != sched.Interval || remote.Hour != sched.Hour ||
					remote.Minute != sched.Minute || remote.Weekday != sched.Weekday {
					sched = *remote
					fmt.Fprintf(os.Stderr, "Schedule updated from StdOut: %s\n", describeSchedule(sched))
				}
				if !remote.Enabled {
					fmt.Fprintln(os.Stderr, "Scanning disabled via StdOut settings — waiting...")
					sleepCtx(ctx, 5*time.Minute)
					continue
				}
			}
		}

		// Calculate next run time
		next := nextRunTime(sched)
		wait := time.Until(next)
		if wait < 0 {
			wait = 1 * time.Minute
		}

		fmt.Fprintf(os.Stderr, "Next scan: %s (in %s)\n", next.Format("2006-01-02 15:04:05"), wait.Round(time.Minute))

		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "Scheduler stopped")
			return
		case <-time.After(wait):
			fmt.Fprintln(os.Stderr, "Running scheduled scan...")
			scanFunc()
		}
	}
}

// fetchRemoteSchedule polls StdOut's API for the user's scan schedule.
// Endpoint: GET /app/api/scanner/schedule
func fetchRemoteSchedule(baseURL, token string) (*Schedule, error) {
	url := strings.TrimRight(baseURL, "/") + "/app/api/scanner/schedule"

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "stdout-scanner/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	var sched Schedule
	if err := json.NewDecoder(resp.Body).Decode(&sched); err != nil {
		return nil, err
	}

	return &sched, nil
}

func nextRunTime(sched Schedule) time.Time {
	now := time.Now()

	switch sched.Interval {
	case "hourly":
		next := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), sched.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.Add(1 * time.Hour)
		}
		return next

	case "daily":
		next := time.Date(now.Year(), now.Month(), now.Day(), sched.Hour, sched.Minute, 0, 0, now.Location())
		if next.Before(now) {
			next = next.Add(24 * time.Hour)
		}
		return next

	case "weekly":
		next := time.Date(now.Year(), now.Month(), now.Day(), sched.Hour, sched.Minute, 0, 0, now.Location())
		// Advance to the target weekday
		daysUntil := (sched.Weekday - int(next.Weekday()) + 7) % 7
		if daysUntil == 0 && next.Before(now) {
			daysUntil = 7
		}
		next = next.Add(time.Duration(daysUntil) * 24 * time.Hour)
		return next

	default:
		// Cron-style: parse and find next occurrence
		// For simplicity, fall back to daily if we can't parse
		next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
		if next.Before(now) {
			next = next.Add(24 * time.Hour)
		}
		return next
	}
}

func describeSchedule(sched Schedule) string {
	timeStr := fmt.Sprintf("%02d:%02d", sched.Hour, sched.Minute)
	switch sched.Interval {
	case "hourly":
		return fmt.Sprintf("every hour at :%02d", sched.Minute)
	case "daily":
		return fmt.Sprintf("daily at %s", timeStr)
	case "weekly":
		days := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
		day := "Sun"
		if sched.Weekday >= 0 && sched.Weekday < 7 {
			day = days[sched.Weekday]
		}
		return fmt.Sprintf("weekly on %s at %s", day, timeStr)
	default:
		return fmt.Sprintf("cron: %s", sched.Interval)
	}
}

func parseTime(s string) (int, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time %q (expected HH:MM)", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, 0, fmt.Errorf("invalid hour in %q", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid minute in %q", s)
	}
	return h, m, nil
}

func parseDayOfWeek(s string) int {
	switch strings.ToLower(s) {
	case "sun", "sunday":
		return 0
	case "mon", "monday":
		return 1
	case "tue", "tuesday":
		return 2
	case "wed", "wednesday":
		return 3
	case "thu", "thursday":
		return 4
	case "fri", "friday":
		return 5
	case "sat", "saturday":
		return 6
	default:
		return 0
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
