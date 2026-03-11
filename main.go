// portpilot — automatic port detection and reverse proxy.
//
// Monitors /proc/net/tcp for new listening ports and dynamically proxies
// them at /proxy/{port}/. Designed to run inside containers alongside
// a primary process (like ttyd, code-server, or any dev server).
//
// Usage:
//
//	portpilot [flags] -- command [args...]
//	portpilot --listen :7681 --base-path /ws/abc123 -- ttyd --port 7682 --writable bash
//
// Flags:
//
//	--listen       Address to listen on (default ":8080")
//	--base-path    Base URL path prefix (default "", read from $PROXY_BASE_PATH)
//	--scan-interval Interval between port scans (default "2s")
//	--ignore       Comma-separated ports to ignore (default: the listen port)
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":7681", "Address to listen on")
	basePath := flag.String("base-path", os.Getenv("PROXY_BASE_PATH"), "Base URL path prefix")
	scanInterval := flag.Duration("scan-interval", 2*time.Second, "Port scan interval")
	ignore := flag.String("ignore", "", "Comma-separated ports to ignore")
	showVersion := flag.Bool("version", false, "Print version and exit")

	// Parse flags up to "--"
	flag.Parse()

	if *showVersion {
		fmt.Println("portpilot", version)
		os.Exit(0)
	}
	cmdArgs := flag.Args()

	// Determine the listen port to auto-ignore.
	_, listenPortStr, _ := net.SplitHostPort(*listen)
	listenPort, _ := strconv.Atoi(listenPortStr)

	ignorePorts := map[int]bool{listenPort: true}
	if *ignore != "" {
		for _, p := range strings.Split(*ignore, ",") {
			if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ignorePorts[port] = true
			}
		}
	}

	// Normalize base path.
	bp := strings.TrimRight(*basePath, "/")

	pp := &PortPilot{
		basePath:    bp,
		ignorePorts: ignorePorts,
		proxies:     make(map[int]*httputil.ReverseProxy),
	}

	// Start the child process if specified.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if len(cmdArgs) > 0 {
		go pp.runChild(ctx, cmdArgs)
	}

	// Start port scanner.
	go pp.scanLoop(ctx, *scanInterval)

	// Start HTTP server.
	mux := http.NewServeMux()
	mux.HandleFunc("/", pp.handler)

	server := &http.Server{Addr: *listen, Handler: mux}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	log.Printf("portpilot listening on %s (base-path: %s)", *listen, bp)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// PortPilot manages port detection and proxying.
type PortPilot struct {
	basePath    string
	ignorePorts map[int]bool

	mu      sync.RWMutex
	proxies map[int]*httputil.ReverseProxy
}

// handler routes requests to either a detected port proxy or returns 404.
func (pp *PortPilot) handler(w http.ResponseWriter, r *http.Request) {
	// Strip base path prefix.
	reqPath := r.URL.Path
	if pp.basePath != "" {
		if !strings.HasPrefix(reqPath, pp.basePath) {
			http.NotFound(w, r)
			return
		}
		reqPath = strings.TrimPrefix(reqPath, pp.basePath)
	}

	// Check for /proxy/{port}/... pattern.
	if strings.HasPrefix(reqPath, "/proxy/") {
		parts := strings.SplitN(strings.TrimPrefix(reqPath, "/proxy/"), "/", 2)
		if len(parts) >= 1 {
			port, err := strconv.Atoi(parts[0])
			if err == nil && port > 0 && port < 65536 {
				pp.mu.RLock()
				proxy, ok := pp.proxies[port]
				pp.mu.RUnlock()
				if ok {
					// Rewrite path to strip /proxy/{port} prefix.
					remainder := "/"
					if len(parts) > 1 {
						remainder = "/" + parts[1]
					}
					r.URL.Path = remainder
					r.Header.Set("X-Forwarded-Prefix", pp.basePath+"/proxy/"+parts[0])
					proxy.ServeHTTP(w, r)
					return
				}
				http.Error(w, fmt.Sprintf("port %d not detected", port), http.StatusBadGateway)
				return
			}
		}
	}

	// Not a proxy request — return info page.
	pp.mu.RLock()
	ports := make([]int, 0, len(pp.proxies))
	for p := range pp.proxies {
		ports = append(ports, p)
	}
	pp.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "portpilot — %d forwarded ports\n\n", len(ports))
	for _, p := range ports {
		fmt.Fprintf(w, "  %s/proxy/%d/\n", pp.basePath, p)
	}
	if len(ports) == 0 {
		fmt.Fprintln(w, "  (no ports detected yet)")
	}
}

// scanLoop periodically scans /proc/net/tcp for new listening ports.
func (pp *PortPilot) scanLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pp.scan()
		}
	}
}

// scan reads /proc/net/tcp and updates the proxy map.
func (pp *PortPilot) scan() {
	ports, err := scanListeningPorts()
	if err != nil {
		return
	}

	pp.mu.Lock()
	defer pp.mu.Unlock()

	// Add new ports.
	for _, port := range ports {
		if pp.ignorePorts[port] {
			continue
		}
		if _, exists := pp.proxies[port]; !exists {
			target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			pp.proxies[port] = httputil.NewSingleHostReverseProxy(target)
			log.Printf("portpilot: detected port %d → %s/proxy/%d/", port, pp.basePath, port)
		}
	}

	// Remove ports that are no longer listening.
	activeSet := make(map[int]bool, len(ports))
	for _, p := range ports {
		activeSet[p] = true
	}
	for port := range pp.proxies {
		if !activeSet[port] {
			delete(pp.proxies, port)
			log.Printf("portpilot: port %d closed", port)
		}
	}
}

// scanListeningPorts reads /proc/net/tcp and returns ports in LISTEN state.
func scanListeningPorts() ([]int, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		// Also try tcp6.
		f, err = os.Open("/proc/net/tcp6")
		if err != nil {
			return nil, err
		}
	}
	defer f.Close()

	var ports []int
	seen := make(map[int]bool)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// State field (index 3): "0A" = LISTEN
		if fields[3] != "0A" {
			continue
		}

		// Local address field (index 1): "0100007F:1F90" or "00000000:1F90"
		parts := strings.SplitN(fields[1], ":", 2)
		if len(parts) != 2 {
			continue
		}
		portHex := parts[1]
		portBytes, err := hex.DecodeString(portHex)
		if err != nil || len(portBytes) < 2 {
			continue
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		if port > 0 && port < 65536 && !seen[port] {
			ports = append(ports, port)
			seen[port] = true
		}
	}

	// Also scan tcp6 if we opened tcp.
	f6, err := os.Open("/proc/net/tcp6")
	if err == nil {
		defer f6.Close()
		scanner6 := bufio.NewScanner(f6)
		scanner6.Scan() // skip header
		for scanner6.Scan() {
			line := strings.TrimSpace(scanner6.Text())
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.SplitN(fields[1], ":", 2)
			if len(parts) != 2 {
				continue
			}
			portBytes, err := hex.DecodeString(parts[1])
			if err != nil || len(portBytes) < 2 {
				continue
			}
			port := int(portBytes[0])<<8 | int(portBytes[1])
			if port > 0 && port < 65536 && !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	return ports, nil
}

// runChild starts and monitors the child process.
func (pp *PortPilot) runChild(ctx context.Context, args []string) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	log.Printf("portpilot: starting child: %s", strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return // normal shutdown
		}
		log.Fatalf("portpilot: child exited: %v", err)
	}
	// Child exited cleanly — shut down portpilot too.
	log.Println("portpilot: child exited, shutting down")
	os.Exit(0)
}
