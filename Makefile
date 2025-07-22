# Makefile for Go Packet Sniffer

BINARY=sniffer
MAIN=main.go

.PHONY: all build run test lint clean

all: build

build:
	go build -o $(BINARY) $(MAIN)

run:
	go run $(MAIN)

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY) 