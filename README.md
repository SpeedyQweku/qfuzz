# qfuzz

qfuzz`(QwekuFuzzer)`, web fuzzer, and more written in Go

## Installation

```bash
go install github.com/SpeedyQweku/qfuzz@v0.2.2
```

## Usage

```bash
qfuzz, fuzz, and more - v0.2.2

INPUT:
   -wordlist, -w string  Wordlist file path
   -list, -l string      Target file path
   -u string[]           Target URL/URLs (-u https://example.com,https://example.org)

OUTPUT:
   -output, -o string  Output file path

MATCHERS:
   -mc string[]  Match HTTP status codes, (default 200-299,301,302,307,401,403,405,500)
   -ms string[]  Match response body with specified string/strings (-ms example,Fuzz)

CONFIGURATIONS:
   -X string               HTTP method To use in the request, (e.g., GET, POST, PUT, DELETE)
   -data, -d string        Data To include in the request body for POST method
   -H string[]             Headers To include in the request, (e.g., 'key1:value1,key2:value2')
   -follow-redirects, -fr  Follow redirects
   -webcache               Detect web caching, (discoveredWebCache.txt)
   -ra, -random-agent      Enable Random User-Agent To use
   -retries int            number of Retries, if status code is 429 (default 5)
   -http2                  use HTTP2 protocol

OPTIMIZATIONS:
   -c int             number of concurrency To use (default 40)
   -timeout, -to int  timeout (seconds) (default 10)

DEBUG:
   -silent  Silent mode
   -debug   Debug mode
```

### GET fuzzing

Fuzz a list of URLs with the wordlists

```bash
qfuzz -w < wordlist.txt > -l < urls.txt >
```

```bash
qfuzz -u < URL >,< URL >... -w < wordlist.txt >
```

### POST fuzzing

Fuzz a list of URLs with the wordlists

```bash
qfuzz -X POST -d "username=admin\&password=password" -w < wordlist.txt > -l < urls.txt >
```

```bash
qfuzz -X POST -d "username=admin\&password=password" -u < URL >,< URL >... -w < wordlist.txt >
```

### GET match string fuzzing

Fuzz and check if a matched string is in

```bash
qfuzz -w < wordlist.txt > -l < urls.txt > -ms example,Fuzz
```

```bash
qfuzz -u < URL >,< URL >... -w < wordlist.txt > -ms example,Fuzz
```
