# qfuzz

qfuzz`(QwekuFuzzer)`, web fuzzer written in Go

## Installation

```bash
go install github.com/SpeedyQweku/gfuzz@v0.0.1
```

## Usage

GET secret fuzzing

Fuzz a list of URLs with the wordlists to find some secret

```bash
qfuzz -w < wordlist.txt > -l < urls.txt >
```

GET match title fuzzing

Fuzz and check if matched title is in

```bash
qfuzz -w < wordlist.txt > -l < urls.txt > -ms example,Fuzz
```
