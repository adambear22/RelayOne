package watchdog

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"nodepass-agent/internal/config"
	"nodepass-agent/internal/process"
)

type processController interface {
	Start() error
	WaitForCredentials(timeout time.Duration) (process.Credentials, error)
	ExitCh() <-chan struct{}
}

type Stats struct {
	TotalRestarts      int       `json:"total_restarts"`
	LastRestartAt      time.Time `json:"last_restart_at"`
	ConsecutiveFailure int       `json:"consecutive_failure"`
}

type Watchdog struct {
	manager    processController
	conf       *config.AgentConf
	workDir    string
	onRestart  func(newCreds process.Credentials)
	maxRetries int
	stopCh     chan struct{}

	mu    sync.Mutex
	stats Stats
	rnd   *rand.Rand

	validateFn func(workDir, masterAddr, apiKey string) (bool, error)
	saveFn     func(workDir string, conf *config.AgentConf) error
}

func New(
	manager processController,
	conf *config.AgentConf,
	workDir string,
	onRestart func(newCreds process.Credentials),
) *Watchdog {
	if conf == nil {
		conf = &config.AgentConf{}
	}
	return &Watchdog{
		manager:    manager,
		conf:       conf,
		workDir:    workDir,
		onRestart:  onRestart,
		maxRetries: 0,
		stopCh:     make(chan struct{}),
		rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
		validateFn: config.Validate,
		saveFn:     config.Save,
	}
}

func (w *Watchdog) SetMaxRetries(maxRetries int) {
	w.maxRetries = maxRetries
}

func (w *Watchdog) Start(ctx context.Context) {
	attempt := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-w.manager.ExitCh():
		}

		for {
			attempt++
			if w.maxRetries > 0 && attempt > w.maxRetries {
				return
			}
			if err := w.restart(ctx, attempt); err == nil {
				attempt = 0
				break
			}

			w.mu.Lock()
			if w.stats.ConsecutiveFailure >= 5 {
				// keep retrying by design, callers can read stats for alerts.
			}
			w.mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-w.stopCh:
				return
			default:
			}
		}
	}
}

func (w *Watchdog) Stop() error {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	return nil
}

func (w *Watchdog) restart(ctx context.Context, attempt int) error {
	delay := w.backoffDelay(attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.stopCh:
		return context.Canceled
	case <-timer.C:
	}

	if err := w.manager.Start(); err != nil {
		w.recordFailure()
		return err
	}

	creds, err := w.manager.WaitForCredentials(30 * time.Second)
	if err != nil {
		w.recordFailure()
		return err
	}

	valid, err := w.validateFn(w.workDir, creds.MasterAddr, creds.APIKey)
	if err != nil || !valid {
		w.recordFailure()
		if err != nil {
			return err
		}
		return process.ErrCredentialsTimeout
	}

	w.conf.MasterAddr = creds.MasterAddr
	w.conf.APIKey = creds.APIKey
	if err := w.saveFn(w.workDir, w.conf); err != nil {
		w.recordFailure()
		return err
	}

	if w.onRestart != nil {
		w.onRestart(creds)
	}

	w.mu.Lock()
	w.stats.TotalRestarts++
	w.stats.LastRestartAt = time.Now()
	w.stats.ConsecutiveFailure = 0
	w.mu.Unlock()

	return nil
}

func (w *Watchdog) recordFailure() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stats.TotalRestarts++
	w.stats.LastRestartAt = time.Now()
	w.stats.ConsecutiveFailure++
}

func (w *Watchdog) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}

func (w *Watchdog) backoffDelay(attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	base := math.Min(float64(attempt*attempt), 60)
	jitterFactor := 1 + (w.rnd.Float64()*0.4 - 0.2)
	if jitterFactor < 0.1 {
		jitterFactor = 0.1
	}
	return time.Duration(base * jitterFactor * float64(time.Second))
}
