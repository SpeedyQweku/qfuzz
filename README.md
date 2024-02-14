# qfuzz

qfuzz`(QwekuFuzzer)`, web fuzzer written in Go

## Installation

```bash
go install github.com/SpeedyQweku/qfuzz@v0.0.5
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
