package prober

import (
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ProbeTarget struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type ProbeResult struct {
	URL         string `json:"url"`
	FinalURL    string `json:"final_url"`
	StatusCode  int    `json:"status_code"`
	ContentLen  int64  `json:"content_length"`
	Title       string `json:"title"`
	Server      string `json:"server"`
	ContentType string `json:"content_type"`
	Error       string `json:"error,omitempty"`
}

type Prober struct {
	client     *http.Client
	delayMs    int
	jitterMs   int
}

func NewProber(timeoutSec int, delayMs int, jitterMs int) *Prober {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &Prober{
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(timeoutSec) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		delayMs:  delayMs,
		jitterMs: jitterMs,
	}
}

func (p *Prober) ProbeOne(target ProbeTarget) ProbeResult {
	if p.delayMs > 0 {
		sleepTime := p.delayMs
		if p.jitterMs > 0 {
			sleepTime += rand.Intn(p.jitterMs)
		}
		time.Sleep(time.Duration(sleepTime) * time.Millisecond)
	}

	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return ProbeResult{URL: target.URL, Error: err.Error()}
	}

	// Default stealth User-Agent if not explicitly provided
	if _, ok := target.Headers["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	}

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return ProbeResult{URL: target.URL, Error: err.Error()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(bodyBytes)

	title := extractTitle(bodyStr)
	finalURL := resp.Request.URL.String()

	return ProbeResult{
		URL:         target.URL,
		FinalURL:    finalURL,
		StatusCode:  resp.StatusCode,
		ContentLen:  resp.ContentLength,
		Title:       title,
		Server:      resp.Header.Get("Server"),
		ContentType: resp.Header.Get("Content-Type"),
	}
}

func (p *Prober) ProbeBatch(targets []ProbeTarget, concurrency int) []ProbeResult {
	if concurrency <= 0 {
		concurrency = 50
	}

	results := make([]ProbeResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target ProbeTarget) {
			defer wg.Done()
			sem <- struct{}{}
			results[idx] = p.ProbeOne(target)
			<-sem
		}(i, t)
	}

	wg.Wait()
	return results
}

func extractTitle(body string) string {
	lowerBody := strings.ToLower(body)
	startIdx := strings.Index(lowerBody, "<title>")
	if startIdx == -1 {
		return ""
	}
	startIdx += 7
	endIdx := strings.Index(lowerBody[startIdx:], "</title>")
	if endIdx == -1 {
		return ""
	}
	title := strings.TrimSpace(body[startIdx : startIdx+endIdx])
	if len(title) > 100 {
		return title[:97] + "..."
	}
	return title
}
