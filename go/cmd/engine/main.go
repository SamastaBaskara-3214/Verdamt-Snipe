package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"verdamt-engine/pkg/jsscanner"
	"verdamt-engine/pkg/prober"
)

type RequestFrame struct {
	Action      string                `json:"action"`
	Targets     []prober.ProbeTarget  `json:"targets"`
	Files       []jsscanner.FileInput `json:"files"`
	Concurrency int                   `json:"concurrency"`
	Timeout     int                   `json:"timeout"`
	DelayMs     int                   `json:"delay_ms"`
	JitterMs    int                   `json:"jitter_ms"`
}

type ResponseFrame struct {
	Status    string                `json:"status"`
	Results   []prober.ProbeResult  `json:"results,omitempty"`
	Findings  []jsscanner.Finding   `json:"findings,omitempty"`
	Endpoints []string              `json:"endpoints,omitempty"`
	Error     string                `json:"error,omitempty"`
}

func main() {
	socketPath := flag.String("socket", "/tmp/verdamt-engine.sock", "Path to Unix Domain Socket")
	flag.Parse()

	// Cleanup old socket file
	_ = os.Remove(*socketPath)

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on socket %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer listener.Close()
	defer os.Remove(*socketPath)

	// Make socket writable by user
	_ = os.Chmod(*socketPath, 0700)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = listener.Close()
		_ = os.Remove(*socketPath)
		os.Exit(0)
	}()

	fmt.Printf("[+] Verdamt Go Engine active on unix://%s\n", *socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	// Allow large payload buffers
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req RequestFrame
		if err := json.Unmarshal(line, &req); err != nil {
			sendError(conn, fmt.Sprintf("invalid JSON payload: %v", err))
			continue
		}

		switch req.Action {
		case "ping":
			sendSuccess(conn, nil)
		case "probe_batch":
			timeout := req.Timeout
			if timeout <= 0 {
				timeout = 5
			}
			concurrency := req.Concurrency
			if concurrency <= 0 {
				concurrency = 100
			}
			p := prober.NewProber(timeout, req.DelayMs, req.JitterMs)
			results := p.ProbeBatch(req.Targets, concurrency)
			sendSuccess(conn, results)
		case "js_scan_batch":
			scanner := jsscanner.NewScanner()
			batchRes := scanner.ScanBatch(req.Files)
			sendJSResult(conn, batchRes.Findings, batchRes.Endpoints)
		default:
			sendError(conn, fmt.Sprintf("unknown action: %s", req.Action))
		}
	}
}

func sendJSResult(conn net.Conn, findings []jsscanner.Finding, endpoints []string) {
	resp := ResponseFrame{
		Status:    "ok",
		Findings:  findings,
		Endpoints: endpoints,
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func sendSuccess(conn net.Conn, results []prober.ProbeResult) {
	resp := ResponseFrame{
		Status:  "ok",
		Results: results,
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func sendError(conn net.Conn, msg string) {
	resp := ResponseFrame{
		Status: "error",
		Error:  msg,
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}
