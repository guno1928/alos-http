package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const fineTuneHealthPath = "/"

var (
	wrkRequestsPerSecPattern = regexp.MustCompile(`(?m)Requests/sec:\s+([0-9]+(?:\.[0-9]+)?)`)
	wrkLatencyPattern        = regexp.MustCompile(`(?m)Latency\s+([^\s]+)`)
	wrkTransferPattern       = regexp.MustCompile(`(?m)Transfer/sec:\s+(.+)$`)
)

type FineTuneScenario struct {
	Name        string
	Connections int
	Threads     int
	Duration    time.Duration
}

type FineTuneResult struct {
	Scenario       FineTuneScenario
	Workers        int
	Listeners      int
	AcceptShards   int
	RequestsPerSec float64
	Latency        string
	TransferPerSec string
	RawOutput      string
}

type FineTuneReport struct {
	WrkPath            string
	AutoInstalledWrk   bool
	WorkerCandidates   []int
	ListenerCandidates []int
	BestWorkerCount    int
	BestListenerCount  int
	BestAcceptShards   int
	BestByScenario     []FineTuneResult
	Results            []FineTuneResult
}

func (report *FineTuneReport) String() string {
	if report == nil {
		return "ALOS finetuner: no report"
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "ALOS finetuner\n")
	fmt.Fprintf(b, "wrk=%s\n", report.WrkPath)
	fmt.Fprintf(b, "worker_candidates=%s\n", intsToCSV(report.WorkerCandidates))
	fmt.Fprintf(b, "listener_candidates=%s\n", intsToCSV(report.ListenerCandidates))
	fmt.Fprintf(b, "applied_workers=%d\n", report.BestWorkerCount)
	fmt.Fprintf(b, "applied_listeners=%d\n", report.BestListenerCount)
	fmt.Fprintf(b, "applied_accept_shards=%d\n", report.BestAcceptShards)
	if report.AutoInstalledWrk {
		b.WriteString("wrk_install=auto-installed\n")
	}
	b.WriteString("\nBest overall\n")
	fmt.Fprintf(b, "- workers=%d listeners=%d accept_shards=%d\n", report.BestWorkerCount, report.BestListenerCount, report.BestAcceptShards)
	b.WriteString("\nBest per scenario\n")
	for _, result := range report.BestByScenario {
		fmt.Fprintf(b, "- %s: workers=%d listeners=%d accept_shards=%d req/s=%.2f latency=%s transfer=%s\n",
			result.Scenario.Name,
			result.Workers,
			result.Listeners,
			result.AcceptShards,
			result.RequestsPerSec,
			result.Latency,
			result.TransferPerSec,
		)
	}
	b.WriteString("\nFull sweep\n")
	for _, result := range report.Results {
		fmt.Fprintf(b, "- %s: workers=%d listeners=%d accept_shards=%d req/s=%.2f latency=%s transfer=%s\n",
			result.Scenario.Name,
			result.Workers,
			result.Listeners,
			result.AcceptShards,
			result.RequestsPerSec,
			result.Latency,
			result.TransferPerSec,
		)
	}
	return b.String()
}

type FineTuneOptions struct {
	WorkerCandidates   []int
	ListenerCandidates []int
	Scenarios          []FineTuneScenario
	AutoInstallWrk     bool
	StartupTimeout     time.Duration
	RequestTimeout     time.Duration
	BindHost           string
}

func DefaultFineTuneOptions() FineTuneOptions {
	return FineTuneOptions{
		WorkerCandidates:   []int{12, 24, 32, 42, 52, 62},
		ListenerCandidates: []int{1, 5, 10},
		Scenarios: []FineTuneScenario{
			{Name: "30 connections / 30 threads", Connections: 30, Threads: 30, Duration: 6 * time.Second},
			{Name: "500 connections / 50 threads", Connections: 500, Threads: 50, Duration: 6 * time.Second},
			{Name: "5000 connections / 50 threads", Connections: 5000, Threads: 50, Duration: 6 * time.Second},
			{Name: "8000 connections / 50 threads", Connections: 8000, Threads: 50, Duration: 6 * time.Second},
		},
		AutoInstallWrk: true,
		StartupTimeout: 10 * time.Second,
		RequestTimeout: 500 * time.Millisecond,
		BindHost:       "127.0.0.1",
	}
}

func (s *Server) FineTune() error {
	_, err := s.FineTuneWithOptions(DefaultFineTuneOptions())
	return err
}

func (s *Server) FineTuneWithOptions(options FineTuneOptions) (*FineTuneReport, error) {
	if s == nil {
		return nil, errors.New("nil server")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("finetuner requires linux amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if serverDoneClosed(s.done) || len(s.listeners) > 0 {
		return nil, errors.New("finetuner must run before the server starts")
	}
	if len(options.WorkerCandidates) == 0 {
		options.WorkerCandidates = DefaultFineTuneOptions().WorkerCandidates
	}
	if len(options.ListenerCandidates) == 0 {
		options.ListenerCandidates = DefaultFineTuneOptions().ListenerCandidates
	}
	if len(options.Scenarios) == 0 {
		options.Scenarios = DefaultFineTuneOptions().Scenarios
	}
	if options.StartupTimeout <= 0 {
		options.StartupTimeout = 10 * time.Second
	}
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = 500 * time.Millisecond
	}
	if options.BindHost == "" {
		options.BindHost = "127.0.0.1"
	}

	wrkPath, autoInstalled, err := ensureWrkAvailable(options.AutoInstallWrk)
	if err != nil {
		return nil, err
	}

	report := &FineTuneReport{
		WrkPath:            wrkPath,
		AutoInstalledWrk:   autoInstalled,
		WorkerCandidates:   append([]int(nil), options.WorkerCandidates...),
		ListenerCandidates: append([]int(nil), options.ListenerCandidates...),
		Results:            make([]FineTuneResult, 0, len(options.WorkerCandidates)*len(options.ListenerCandidates)*len(options.Scenarios)),
	}

	for _, listeners := range options.ListenerCandidates {
		for _, workers := range options.WorkerCandidates {
			for _, scenario := range options.Scenarios {
				log.Printf("[FINETUNE] scenario=%q workers=%d listeners=%d accept_shards=%d duration=%s", scenario.Name, workers, listeners, minInt(workers, listeners), formatWrkDuration(scenario.Duration))
				result, runErr := s.runFineTuneScenario(wrkPath, workers, listeners, scenario, options)
				if runErr != nil {
					return nil, fmt.Errorf("finetune failed for scenario=%q workers=%d listeners=%d accept_shards=%d: %w", scenario.Name, workers, listeners, minInt(workers, listeners), runErr)
				}
				report.Results = append(report.Results, result)
			}
		}
	}

	report.BestByScenario = bestByScenario(report.Results)
	report.BestWorkerCount, report.BestListenerCount = chooseOverallBestConfig(report.Results)
	report.BestAcceptShards = minInt(report.BestWorkerCount, report.BestListenerCount)
	s.config.WorkerCount = report.BestWorkerCount
	s.config.Listeners = report.BestListenerCount

	log.Print(report.String())
	return report, nil
}

func (s *Server) runFineTuneScenario(wrkPath string, workers int, listeners int, scenario FineTuneScenario, options FineTuneOptions) (FineTuneResult, error) {
	var (
		benchServer *Server
		url         string
		errCh       chan error
	)
	for attempt := 0; attempt < 10; attempt++ {
		addr, err := reserveFineTuneAddr(options.BindHost)
		if err != nil {
			return FineTuneResult{}, err
		}
		benchServer = New(s.fineTuneConfig(addr, workers, listeners))
		benchServer.Router.GET(fineTuneHealthPath, func(req *Request, resp *Response) {
			resp.Status(200).JSONString(`{"status":"ok"}`)
		})
		errCh = make(chan error, 1)
		go func(server *Server) {
			errCh <- server.ListenAndServe()
		}(benchServer)
		url, err = fineTuneURL(addr, options.BindHost)
		if err != nil {
			return FineTuneResult{}, err
		}
		if err := waitForFineTuneServer(url, options.StartupTimeout, options.RequestTimeout, errCh); err != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = benchServer.Shutdown(shutdownCtx)
			cancel()
			if isRetryableFineTuneStartupError(err) {
				select {
				case <-errCh:
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}
			return FineTuneResult{}, fmt.Errorf("startup check failed: %w", err)
		}
		break
	}
	if benchServer == nil || errCh == nil || url == "" {
		return FineTuneResult{}, errors.New("failed to start benchmark server")
	}

	log.Printf("[FINETUNE] wrk start scenario=%q workers=%d listeners=%d threads=%d connections=%d duration=%s url=%s",
		scenario.Name,
		workers,
		listeners,
		scenario.Threads,
		scenario.Connections,
		formatWrkDuration(scenario.Duration),
		url,
	)
	output, runErr := runWrkScenario(wrkPath, url, scenario)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := benchServer.Shutdown(shutdownCtx)
	serveErr := <-errCh
	if shutdownErr != nil {
		return FineTuneResult{}, fmt.Errorf("shutdown failed: %w", shutdownErr)
	}
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
		return FineTuneResult{}, fmt.Errorf("server failed: %w", serveErr)
	}
	if runErr != nil {
		return FineTuneResult{}, fmt.Errorf("wrk run failed: %w", runErr)
	}

	parsed, err := parseWrkOutput(output)
	if err != nil {
		return FineTuneResult{}, err
	}
	parsed.Scenario = scenario
	parsed.Workers = workers
	parsed.Listeners = listeners
	parsed.AcceptShards = minInt(workers, listeners)
	parsed.RawOutput = output
	log.Printf("[FINETUNE] wrk result scenario=%q workers=%d listeners=%d accept_shards=%d req/s=%.2f latency=%s transfer=%s",
		parsed.Scenario.Name,
		parsed.Workers,
		parsed.Listeners,
		parsed.AcceptShards,
		parsed.RequestsPerSec,
		parsed.Latency,
		parsed.TransferPerSec,
	)
	return parsed, nil
}

func isRetryableFineTuneStartupError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EEXIST) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "address already in use") || strings.Contains(message, "file exists")
}

func (s *Server) fineTuneConfig(addr string, workers int, listeners int) Config {
	cfg := s.config
	cfg.Addr = addr
	cfg.HTTPAddr = "-"
	cfg.PlainHTTP = true
	cfg.DisableHTTP2 = true
	cfg.IdleTimeout = time.Second
	cfg.WorkerCount = workers
	cfg.Debug = false
	cfg.LogRequests = false
	if listeners <= 0 {
		listeners = 1
	}
	cfg.Listeners = listeners
	cfg.ACME = nil
	cfg.Certs = nil
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	cfg.DefaultDomain = ""
	return cfg
}

func startFineTuneServer(server *Server, bindHost string, listenerCount int) (string, chan error, error) {
	workers := server.config.WorkerCount
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0) + runtime.GOMAXPROCS(0)/2
	}
	if workers < 1 {
		workers = 1
	}
	if listenerCount < 1 {
		listenerCount = 1
	}
	listenerCount = ioUringListenerCount(listenerCount)
	if workers > listenerCount {
		workers = listenerCount
	}
	runtime.GOMAXPROCS(workers)
	maybeRaiseProcessFileLimit()
	logIOUringStartupProbe()
	server.Router.Build()
	server.computeFastDispatch()

	listeners, err := allocateFineTuneListeners(bindHost, listenerCount)
	if err != nil {
		return "", nil, err
	}
	addr := listeners[0].Addr().String()
	server.listeners = listeners
	log.Println("=== ALOS HTTP Server (Plain HTTP/1.1 + HTTP/2 prior knowledge) ===")
	log.Printf("Listening on http://%s (%d listener(s))", addr, len(listeners))

	errCh := make(chan error, 1)
	go func() {
		if started, serveErr := server.tryServeWithIOUringPlainWorkers(listeners); started || serveErr != nil {
			errCh <- serveErr
			return
		}
		errCh <- ErrIOUringRequired
	}()
	return addr, errCh, nil
}

func allocateFineTuneListeners(bindHost string, listenerCount int) ([]net.Listener, error) {
	if listenerCount < 1 {
		listenerCount = 1
	}
	listenerCount = ioUringListenerCount(listenerCount)
	first, err := createListeners(net.JoinHostPort(bindHost, "0"), 1)
	if err != nil {
		return nil, err
	}
	if listenerCount == 1 {
		return first, nil
	}
	addr := first[0].Addr().String()
	more, err := createListeners(addr, listenerCount-1)
	if err != nil {
		for _, ln := range first {
			_ = ln.Close()
		}
		return nil, err
	}
	listeners := make([]net.Listener, 0, listenerCount)
	listeners = append(listeners, first...)
	listeners = append(listeners, more...)
	return listeners, nil
}

func reserveFineTuneAddr(bindHost string) (string, error) {
	listener, err := net.Listen("tcp4", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		return "", err
	}
	addr := listener.Addr().String()
	if closeErr := listener.Close(); closeErr != nil {
		return "", closeErr
	}
	return addr, nil
}

func waitForFineTuneServer(url string, startupTimeout time.Duration, requestTimeout time.Duration, errCh <-chan error) error {
	deadline := time.Now().Add(startupTimeout)
	client := &http.Client{Timeout: requestTimeout}
	lastFailure := "no response received"
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err != nil {
				return err
			}
			return errors.New("benchmark server exited before becoming ready")
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastFailure = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		} else {
			lastFailure = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("benchmark server did not become ready within %s: last failure: %s", startupTimeout, lastFailure)
}

func fineTuneURL(addr string, bindHost string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	clientHost := bindHost
	if clientHost == "" || clientHost == "0.0.0.0" {
		clientHost = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(clientHost, port) + fineTuneHealthPath, nil
}

func runWrkScenario(wrkPath string, url string, scenario FineTuneScenario) (string, error) {
	cmd := exec.Command(
		wrkPath,
		"-t", strconv.Itoa(scenario.Threads),
		"-c", strconv.Itoa(scenario.Connections),
		"-d", formatWrkDuration(scenario.Duration),
		url,
	)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wrk failed: %w\n%s", err, combined.String())
	}
	return combined.String(), nil
}

func parseWrkOutput(output string) (FineTuneResult, error) {
	requestsMatch := wrkRequestsPerSecPattern.FindStringSubmatch(output)
	if len(requestsMatch) != 2 {
		return FineTuneResult{}, errors.New("failed to parse wrk Requests/sec output")
	}
	requestsPerSec, err := strconv.ParseFloat(requestsMatch[1], 64)
	if err != nil {
		return FineTuneResult{}, err
	}
	latency := "unknown"
	if latencyMatch := wrkLatencyPattern.FindStringSubmatch(output); len(latencyMatch) == 2 {
		latency = latencyMatch[1]
	}
	transfer := "unknown"
	if transferMatch := wrkTransferPattern.FindStringSubmatch(output); len(transferMatch) == 2 {
		transfer = strings.TrimSpace(transferMatch[1])
	}
	return FineTuneResult{
		RequestsPerSec: requestsPerSec,
		Latency:        latency,
		TransferPerSec: transfer,
	}, nil
}

func bestByScenario(results []FineTuneResult) []FineTuneResult {
	best := make(map[string]FineTuneResult)
	for _, result := range results {
		current, ok := best[result.Scenario.Name]
		if !ok || result.RequestsPerSec > current.RequestsPerSec || (result.RequestsPerSec == current.RequestsPerSec && result.Listeners < current.Listeners) || (result.RequestsPerSec == current.RequestsPerSec && result.Listeners == current.Listeners && result.Workers < current.Workers) {
			best[result.Scenario.Name] = result
		}
	}
	names := make([]string, 0, len(best))
	for name := range best {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]FineTuneResult, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, best[name])
	}
	return ordered
}

func chooseOverallBestConfig(results []FineTuneResult) (int, int) {
	if len(results) == 0 {
		return 0, 0
	}
	type aggregate struct {
		wins  int
		total float64
	}
	type configKey struct {
		workers   int
		listeners int
	}
	aggregates := make(map[configKey]aggregate)
	for _, result := range results {
		key := configKey{workers: result.Workers, listeners: result.Listeners}
		entry := aggregates[key]
		entry.total += result.RequestsPerSec
		aggregates[key] = entry
	}
	for _, best := range bestByScenario(results) {
		key := configKey{workers: best.Workers, listeners: best.Listeners}
		entry := aggregates[key]
		entry.wins++
		aggregates[key] = entry
	}
	bestKey := configKey{}
	var best aggregate
	for key, entry := range aggregates {
		if bestKey.workers == 0 || entry.wins > best.wins || (entry.wins == best.wins && entry.total > best.total) || (entry.wins == best.wins && entry.total == best.total && key.listeners < bestKey.listeners) || (entry.wins == best.wins && entry.total == best.total && key.listeners == bestKey.listeners && key.workers < bestKey.workers) {
			bestKey = key
			best = entry
		}
	}
	return bestKey.workers, bestKey.listeners
}

func chooseOverallBestWorker(results []FineTuneResult) int {
	workers, _ := chooseOverallBestConfig(results)
	return workers
}

func formatWrkDuration(duration time.Duration) string {
	seconds := int(duration.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds) + "s"
}

func ensureWrkAvailable(autoInstall bool) (string, bool, error) {
	if wrkPath, err := exec.LookPath("wrk"); err == nil {
		return wrkPath, false, nil
	}
	if !autoInstall {
		return "", false, errors.New("wrk not found in PATH")
	}
	attempted, installErr := tryInstallWrk()
	if wrkPath, err := exec.LookPath("wrk"); err == nil {
		return wrkPath, true, nil
	}
	if installErr != nil {
		return "", false, fmt.Errorf("wrk not found and auto-install failed: %w", installErr)
	}
	return "", false, fmt.Errorf("wrk not found after auto-install attempts: %s", strings.Join(attempted, ", "))
}

func tryInstallWrk() ([]string, error) {
	commands := wrkInstallCommands()
	attempted := make([]string, 0, len(commands))
	var lastErr error
	for _, command := range commands {
		if _, err := exec.LookPath(command.binary); err != nil {
			continue
		}
		attempted = append(attempted, command.label)
		cmd := exec.Command(command.binary, command.args...)
		var combined bytes.Buffer
		cmd.Stdout = &combined
		cmd.Stderr = &combined
		if err := cmd.Run(); err != nil {
			lastErr = fmt.Errorf("%s: %w (%s)", command.label, err, strings.TrimSpace(combined.String()))
			continue
		}
		if _, err := exec.LookPath("wrk"); err == nil {
			return attempted, nil
		}
	}
	if len(attempted) == 0 {
		return attempted, errors.New("no supported package manager found for wrk auto-install")
	}
	if lastErr != nil {
		return attempted, lastErr
	}
	return attempted, nil
}

type wrkInstallCommand struct {
	binary string
	args   []string
	label  string
}

func wrkInstallCommands() []wrkInstallCommand {
	switch runtime.GOOS {
	case "linux":
		return []wrkInstallCommand{
			{binary: "apt-get", args: []string{"update"}, label: "apt-get update"},
			{binary: "apt-get", args: []string{"install", "-y", "wrk"}, label: "apt-get install wrk"},
			{binary: "dnf", args: []string{"install", "-y", "wrk"}, label: "dnf install wrk"},
			{binary: "yum", args: []string{"install", "-y", "wrk"}, label: "yum install wrk"},
			{binary: "apk", args: []string{"add", "--no-cache", "wrk"}, label: "apk add wrk"},
			{binary: "pacman", args: []string{"-Sy", "--noconfirm", "wrk"}, label: "pacman install wrk"},
		}
	case "darwin":
		return []wrkInstallCommand{{binary: "brew", args: []string{"install", "wrk"}, label: "brew install wrk"}}
	case "windows":
		return []wrkInstallCommand{
			{binary: "choco", args: []string{"install", "wrk", "-y"}, label: "choco install wrk"},
			{binary: "scoop", args: []string{"install", "wrk"}, label: "scoop install wrk"},
		}
	default:
		return nil
	}
}

func serverDoneClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func intsToCSV(values []int) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}
