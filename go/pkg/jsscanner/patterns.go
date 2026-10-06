package jsscanner

import "regexp"

type NamedPattern struct {
	Name    string
	Title   string
	Pattern *regexp.Regexp
}

var SecretPatterns = []NamedPattern{
	{
		Name:    "google_api",
		Title:   "JS Secret: Google Api",
		Pattern: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	},
	{
		Name:    "firebase",
		Title:   "JS Secret: Firebase",
		Pattern: regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
	},
	{
		Name:    "aws_access_key",
		Title:   "JS Secret: Aws Access Key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		Name:    "aws_secret_key",
		Title:   "JS Secret: Aws Secret Key",
		Pattern: regexp.MustCompile(`(?i)(?:aws_secret|aws_secret_key|secret_key)[\s:=]+['"]([a-zA-Z0-9/+=]{40})['"]`),
	},
	{
		Name:    "amazon_mws",
		Title:   "JS Secret: Amazon Mws",
		Pattern: regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	},
	{
		Name:    "slack_token",
		Title:   "JS Secret: Slack Token",
		Pattern: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
	},
	{
		Name:    "slack_webhook",
		Title:   "JS Secret: Slack Webhook",
		Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
	},
	{
		Name:    "github_token",
		Title:   "JS Secret: Github Token",
		Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	},
	{
		Name:    "stripe_key",
		Title:   "JS Secret: Stripe Key",
		Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	},
	{
		Name:    "ssh_key",
		Title:   "JS Secret: Ssh Key",
		Pattern: regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
	},
	{
		Name:    "jwt_token",
		Title:   "JS Secret: Jwt Token",
		Pattern: regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]*`),
	},
	{
		Name:    "email",
		Title:   "JS Secret: Email",
		Pattern: regexp.MustCompile(`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`),
	},
	{
		Name:    "internal_ip",
		Title:   "JS Secret: Internal Ip",
		Pattern: regexp.MustCompile(`10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}`),
	},
	{
		Name:    "generic_secret",
		Title:   "JS Secret: Generic Secret",
		Pattern: regexp.MustCompile(`(?i)(?:key|secret|token|password|auth|creds|api_key|access_key)[\s:=]+['"]([a-zA-Z0-9_\-]{16,})['"]`),
	},
}

var EndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)['"](/api/[a-zA-Z0-9_\-/.]+)['"]`),
	regexp.MustCompile(`(?i)['"](/v[0-9]+/[a-zA-Z0-9_\-/.]+)['"]`),
	regexp.MustCompile(`(?i)fetch\s*\(\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile("(?i)fetch\\s*\\(\\s*[`](/[a-zA-Z0-9_\\-/.?&=${}]+)[`]"),
	regexp.MustCompile(`(?i)axios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile(`(?i)axios\s*\(\s*\{[^}]*?url\s*:\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile(`(?i)\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile(`(?i)(?:\$\.ajax|\$\.get|\$\.post|\$\.getJSON)\s*\(\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile(`(?i)url\s*:\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile(`(?i)['"](/graphql[a-zA-Z0-9_\-/]*)['"]`),
	regexp.MustCompile(`(?i)['"](wss?://[a-zA-Z0-9_\-./]+)['"]`),
	regexp.MustCompile(`(?i)['"]((https?://[a-zA-Z0-9_\-.]+)/[a-zA-Z0-9_\-/.?&=]+)['"]`),
	regexp.MustCompile(`(?i)(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*['"](/[a-zA-Z0-9_\-/.:]+)['"]`),
	regexp.MustCompile(`(?i)(?:path|endpoint|route|uri|href|action|redirect)\s*(?::|=)\s*['"](/[a-zA-Z0-9_\-/.]+)['"]`),
	regexp.MustCompile(`(?i)['"](/(?:admin|dashboard|internal|debug|config|settings|console|api|auth|login|register|upload|download|export|import|webhook|callback|notify|health|status|metrics|graphql)[a-zA-Z0-9_\-/]*)['"]`),
}

var NoisePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/$`),
	regexp.MustCompile(`^/[a-z]$`),
	regexp.MustCompile(`(?i)\.(?:css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$`),
	regexp.MustCompile(`^/node_modules/`),
	regexp.MustCompile(`^/bower_components/`),
	regexp.MustCompile(`(?i)^/static/(?:css|js|img|fonts)/`),
}

var DisallowedHosts = map[string]bool{
	"www.w3.org":    true,
	"w3.org":        true,
	"react.dev":     true,
	"github.com":    true,
	"instagram.com": true,
	"facebook.com":  true,
	"twitter.com":   true,
	"x.com":         true,
}
