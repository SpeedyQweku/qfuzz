# qfuzz

qfuzz`(QwekuFuzzer)`, web fuzzer and more written in Go

## Installation

```bash
go install github.com/SpeedyQweku/qfuzz@v0.1.1
```

## Usage

```bash
qfuzz, fuzz and more - v0.1.1

INPUT:
   -wordlist, -w string  Wordlist file path
   -list, -l string      Target file path
   -u string[]           Target url/urls (-u https://example.com,https://example.org)

OUTPUT:
   -output, -o string  Output file path

MATCHERS:
   -match-strings, -ms string[]  match response with specified string/strings (-mt example,Fuzz)

CONFIGURATIONS:
   -X string               HTTP method To use in the request, (e.g., GET, POST, PUT, DELETE)
   -data, -d string        Data To include in the request body for POST method
   -H string[]             Headers To include in the request, (e.g., 'key1:value1,key2:value2')
   -follow-redirects, -fr  Follow redirects
   -webcache               Detect web caching, (discovedWebCache.txt)
   -random-agent           Enable Random User-Agent To use (default true)
   -Retries int            number of Retries, if status code is 429 (default 5)
   -http2                  use HTTP2 protocol

OPTIMIZATIONS:
   -c int             number of concurrency To use (default 40)
   -timeout, -To int  timeout (seconds) (default 10)

DEBUG:
   -v, -Verbose  Verbose mode
   -s, -Silent   Silent mode (default true)

```

### GET secret fuzzing

Fuzz a list of URLs with the wordlists to find some secret

```bash
qfuzz -w < wordlist.txt > -l < urls.txt >
```

### GET match title fuzzing

Fuzz and check if matched title is in

```bash
qfuzz -w < wordlist.txt > -l < urls.txt > -ms example,Fuzz
```
