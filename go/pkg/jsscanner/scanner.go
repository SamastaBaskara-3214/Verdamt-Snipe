package jsscanner

import "regexp"

type FileInput struct {
	URL     string  `json:"url"`
	Content string  `json:"content"`
	Status  int     `json:"status"`
	Time    float64 `json:"time"`
	WAF     string  `json:"waf"`
}

type Finding struct {
	Type   string  `json:"type"`
	Title  string  `json:"title"`
	URL    string  `json:"url"`
	Detail string  `json:"detail"`
	WAF    string  `json:"waf"`
	Time   float64 `json:"time"`
	Status int     `json:"status"`
}

type BatchResult struct {
	Findings  []Finding `json:"findings"`
	Endpoints []string  `json:"endpoints"`
}

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) isNoise(endpoint string) bool {
	for _, ch := range []string{"{", "}", "`", "\\"} {
		for i := 0; i < len(endpoint); i++ {
			if string(endpoint[i]) == ch {
				return true
			}
		}
	}

	for _, p := range NoisePatterns {
		if p.MatchString(endpoint) {
			return true
		}
	}
	return false
}

var httpHostRegex = regexp.MustCompile(`(?i)^https?://([^/]+)`)

func (s *Scanner) checkHostNoise(endpoint string) bool {
	matches := httpHostRegex.FindStringSubmatch(endpoint)
	if len(matches) > 1 {
		host := matches[1]
		if DisallowedHosts[host] {
			return true
		}
	}
	return false
}

func (s *Scanner) ScanFile(file FileInput) ([]Finding, []string) {
	var findings []Finding
	endpointSet := make(map[string]bool)
	seenDetails := make(map[string]bool)

	// Secret scanning
	for _, p := range SecretPatterns {
		matches := p.Pattern.FindAllString(file.Content, -1)
		for _, m := range matches {
			if !seenDetails[m] {
				seenDetails[m] = true
				findings = append(findings, Finding{
					Type:   "js_secret_" + p.Name,
					Title:  p.Title,
					URL:    file.URL,
					Detail: m,
					WAF:    file.WAF,
					Time:   file.Time,
					Status: file.Status,
				})
			}
		}
	}

	// Endpoint scanning
	for _, p := range EndpointPatterns {
		submatches := p.FindAllStringSubmatch(file.Content, -1)
		for _, sub := range submatches {
			if len(sub) > 1 {
				ep := sub[1]
				// Trim trailing slashes
				for len(ep) > 0 && ep[len(ep)-1] == '/' {
					ep = ep[:len(ep)-1]
				}
				if len(ep) == 0 {
					continue
				}

				if s.isNoise(ep) || s.checkHostNoise(ep) {
					continue
				}

				if len(ep) >= 3 && (ep[0] == '/' || httpHostRegex.MatchString(ep)) {
					endpointSet[ep] = true
				}
			}
		}
	}

	var endpoints []string
	for ep := range endpointSet {
		endpoints = append(endpoints, ep)
		title := "JS Endpoint: " + ep
		if len(ep) > 60 {
			title = "JS Endpoint: " + ep[:60]
		}
		findings = append(findings, Finding{
			Type:   "js_endpoint",
			Title:  title,
			URL:    file.URL,
			Detail: ep,
			WAF:    file.WAF,
			Time:   file.Time,
			Status: file.Status,
		})
	}

	return findings, endpoints
}

func (s *Scanner) ScanBatch(files []FileInput) BatchResult {
	if len(files) == 0 {
		return BatchResult{}
	}

	type res struct {
		findings  []Finding
		endpoints []string
	}

	ch := make(chan res, len(files))
	// Worker pool concurrency guard (max 32 concurrent goroutines per batch)
	maxWorkers := 32
	if len(files) < maxWorkers {
		maxWorkers = len(files)
	}
	sem := make(chan struct{}, maxWorkers)

	for _, f := range files {
		sem <- struct{}{}
		go func(file FileInput) {
			defer func() { <-sem }()
			fds, eps := s.ScanFile(file)
			ch <- res{findings: fds, endpoints: eps}
		}(f)
	}

	var allFindings []Finding
	globalEndpoints := make(map[string]bool)

	for i := 0; i < len(files); i++ {
		r := <-ch
		allFindings = append(allFindings, r.findings...)
		for _, ep := range r.endpoints {
			globalEndpoints[ep] = true
		}
	}

	var endpoints []string
	for ep := range globalEndpoints {
		endpoints = append(endpoints, ep)
	}

	return BatchResult{
		Findings:  allFindings,
		Endpoints: endpoints,
	}
}
