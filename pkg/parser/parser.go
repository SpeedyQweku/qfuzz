package parser

import (
	"github.com/projectdiscovery/goflags"
	
	"github.com/SpeedyQweku/qfuzz/pkg/config"
)


func Parse() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("qfuzz, fuzz and more - " + config.Version)
	flagSet.CreateGroup("input", "INPUT OPTIONS",
		flagSet.StringVarP(&config.Cfg.WordlistFile, "w", "wordlist", "", "Wordlist file path"),
		flagSet.StringVarP(&config.Cfg.UrlFile, "l", "list", "", "Target URL file path"),
		flagSet.StringSliceVar(&config.Cfg.UrlString, "u", nil, "Target URL(s) (-u https://example.com,https://example.org)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("output", "OUTPUT OPTIONS",
		flagSet.StringVarP(&config.Cfg.OutputFile, "o", "output", "", "Output file path"),
	)
	flagSet.CreateGroup("matchers", "MATCHERS OPTIONS",
		flagSet.StringSliceVar(&config.Cfg.MatchStatus, "mc", nil, "Match HTTP status code(s), (default 200-299,301,302,307,401,403,405,500)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&config.Cfg.MatchStrings, "ms", nil, "Match response body with specified string(s) (-ms example,string)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&config.Cfg.MatchContentSize, "ml", nil, "Match HTTP response size", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("Filter", "FILTER OPTIONS",
		flagSet.StringSliceVar(&config.Cfg.FilterStatus, "fc", nil, "Filter HTTP status code(s). eg (-fc 500,202)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&config.Cfg.FilterStrings, "fs", nil, "Filter response body with specified string(s). eg (-fs example,string)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&config.Cfg.FilterContentSize, "fl", nil, "Filter HTTP response size. eg (-fl 4343,433)", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("configurations ", "CONFIGURATIONS OPTIONS",
		flagSet.StringVar(&config.Cfg.HttpMethod, "X", "", "HTTP method To use in the request, (e.g., GET, POST, PUT, DELETE)"),
		flagSet.StringVarP(&config.Cfg.PostData, "d", "data", "", "Data To include in the request body for POST method"),
		flagSet.StringSliceVar(&config.Cfg.Headers, "H", nil, "Headers To include in the request, (e.g., 'key1:value1,key2:value2')", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&config.Cfg.FollowRedirect, "fr", "follow-redirects", false, "Follow redirects"),
		flagSet.BoolVar(&config.Cfg.WebCache, "webcache", false, "Detect web caching, (discoveredWebCache.txt)"),
		flagSet.BoolVarP(&config.Cfg.RandomUserAgent, "random-agent", "ra", false, "Enable Random User-Agent To use"),
		flagSet.IntVar(&config.Cfg.Retries, "retries", 5, "number of Retries, if status code is 429"),
		flagSet.BoolVar(&config.Cfg.Http2, "http2", false, "use HTTP2 protocol"),
	)
	flagSet.CreateGroup("optimizations", "OPTIMIZATIONS OPTIONS",
		flagSet.IntVar(&config.Cfg.Concurrency, "c", 40, "number of concurrency To use"),
		flagSet.IntVarP(&config.Cfg.To, "to", "timeout", 10, "timeout (seconds)"),
	)
	flagSet.CreateGroup("debug", "DEBUG OPTIONS",
		flagSet.BoolVar(&config.Cfg.Silent, "silent", false, "Silent mode"),
		flagSet.BoolVar(&config.Cfg.Debug, "debug", false, "Debug mode"),
	)

	_ = flagSet.Parse()
}
