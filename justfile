#!/usr/bin/env -S just --justfile

# vi: ft=just ts=4 sts=4 expandtab

exe := "pcap-to-ipfix"
outdir := "testing_dir"
test_pcap_file := "test-netflow.pcap"
pcap_file := "netflow.pcap"

# Show the list of possible commands.
run: build
    rm -rf {{outdir}}
    rm -f ./ipfix-dump/*.ipfix
    mkdir {{outdir}}
    ./{{exe}} {{pcap_file}} {{outdir}}
    cp {{outdir}}/*.ipfix ./ipfix-dump/

_list:
    @just --list --list-prefix "····" --unsorted --justfile {{ justfile() }}

clean:
    rm -f {{exe}}

build: clean
    go build ./...

fmt:
    go fmt ./...

rebuild: clean build run

[working-directory: "ipfix-dump"]
container:
    # run just run from ipfix-dump working directory
    @just build

[working-directory: "ipfix-dump"]
test:
    # run just run from ipfix-dump working directory
    @just run
