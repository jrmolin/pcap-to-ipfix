#!/usr/bin/env -S just --justfile

# vi: ft=justfile ts=4 sts=4 et

exe := "pcap-to-ipfix"
outdir := "testing_dir"

# Show the list of possible commands.
_list:
    @just --list --list-prefix "····" --unsorted --justfile {{ justfile() }}

clean:
    rm -f {{exe}}

build: clean
    go build ./...

fmt:
    go fmt ./...

run:
    rm -rf {{outdir}}
    mkdir {{outdir}}
    ./{{exe}} ./netflow.pcap {{outdir}}
    cp {{outdir}}/*.ipfix ~/ipfix-dump/

