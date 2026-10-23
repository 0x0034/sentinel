package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type Chromium struct {
	Binary      string
	NoSandbox   bool
	Timeout     time.Duration
	OutputLimit int
}

func (c *Chromium) executable() (string, error) {
	if c.Binary != "" {
		return exec.LookPath(c.Binary)
	}
	candidates := []string{"chromium", "chromium-browser", "google-chrome"}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("Chromium executable unavailable")
}

func (c *Chromium) Render(ctx context.Context, url string) ([]byte, error) {
	binary, err := c.executable()
	if err != nil {
		return nil, errors.New("Chromium executable unavailable")
	}
	profile, err := os.MkdirTemp("", "sentinel-chromium-")
	if err != nil {
		return nil, errors.New("cannot create Chromium temporary profile")
	}
	defer os.RemoveAll(profile)
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	navigation := timeout - 5*time.Second
	if navigation < time.Millisecond {
		navigation = time.Millisecond
	}
	args := []string{"--headless", "--dump-dom", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-extensions", "--disable-dev-shm-usage", "--user-data-dir=" + profile, "--disk-cache-dir=" + filepath.Join(profile, "cache"), fmt.Sprintf("--timeout=%d", navigation.Milliseconds())}
	if c.NoSandbox {
		args = append(args, "--no-sandbox")
	}
	args = append(args, url)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "TMPDIR=" + profile, "XDG_CONFIG_HOME=" + profile, "XDG_CACHE_HOME=" + filepath.Join(profile, "cache")}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = kill
	cmd.WaitDelay = 2 * time.Second
	defer kill()
	limit := c.OutputLimit
	if limit <= 0 {
		limit = 8 << 20
	}
	output := &limitedOutput{limit: limit, cancel: cancel}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if output.exceeded {
		return nil, errors.New("Chromium response exceeds size limit")
	}
	if ctx.Err() != nil {
		return nil, errors.New("Chromium navigation canceled or timed out")
	}
	if err != nil {
		return nil, errors.New("Chromium process failed")
	}
	return output.body.Bytes(), nil
}

type limitedOutput struct {
	body     bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	exceeded bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	remaining := w.limit - w.body.Len()
	if len(p) > remaining {
		w.body.Write(p[:remaining])
		w.exceeded = true
		w.cancel()
	} else {
		w.body.Write(p)
	}
	return len(p), nil
}
