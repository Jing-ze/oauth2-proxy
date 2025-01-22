package validation

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/options"
	"github.com/Jing-ze/oauth2-proxy/pkg/util"
)

// Validate checks that required options are set and validates those that they
// are of the correct format
func Validate(o *options.Options) error {
	msgs := validateCookie(o.Cookie)
	msgs = append(msgs, validateProviders(o)...)

	var redirectURL *url.URL
	redirectURL, msgs = parseURL(o.RawRedirectURL, "redirect", msgs)
	o.SetRedirectURL(redirectURL)
	if o.RawRedirectURL == "" && !o.Cookie.Secure && !o.ReverseProxy {
		util.Logger.Info("WARNING: no explicit redirect URL: redirects will default to insecure HTTP")
	}

	msgs = append(msgs, validateMatchRules(o.MatchRules)...)
	o.SetMatchRuleDomainDefault()

	if len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}

func validateMatchRules(matchRules options.MatchRules) []string {
	msgs := []string{}

	// 检查 RuleList 的每一个 Rule
	for _, rule := range matchRules.RuleList {
		// 验证 Path 和 Rule
		if rule.Path == "" {
			msgs = append(msgs, fmt.Sprintf("Rule: %+v, Path cannot be empty", rule))
		}
		if rule.Rule == "" {
			msgs = append(msgs, fmt.Sprintf("Rule: %+v, Rule cannot be empty", rule))
		}
	}
	return msgs
}
