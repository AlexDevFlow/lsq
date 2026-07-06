# lsq

A command-line client for [LocalSend](https://localsend.org). Send and receive
files between devices on the same network from a terminal. It speaks to the
normal LocalSend apps, so you can push a file from your phone to a headless
server, or the other way around.

I wrote it because LocalSend wants a GUI on both ends, which is no use on a
server, over SSH, or from a script.

## Install

From source (needs a recent Rust):

```
cargo install --path .
```

Or build the Docker image and run a receiver on a box that's always on:

```
docker build -t lsq .
docker run --network host -v ~/inbox:/data lsq
```

Discovery uses UDP multicast, so the container needs `--network host`.

## Usage

See who's on the network:

```
lsq list
```

Send files. If more than one peer is around it asks which one:

```
lsq send photo.jpg notes.pdf
lsq send ~/backup --to "Kitchen Pi"
```

Receive. It asks before accepting each transfer by default:

```
lsq receive --dest ~/Downloads
```

Run it as an always-on receiver that takes everything (handy on a server):

```
lsq receive --dest /srv/inbox --yes
```

`--to` takes an alias, the start of a fingerprint, or a plain `ip` / `ip:port`
if discovery isn't turning the peer up.

Share files the other way round: the peer fetches them from you. This also
covers devices without LocalSend, since the link works in any browser:

```
lsq share slides.pdf photos/
```

It prints a `http://...` URL to open on the other device. Another lsq (or any
client that speaks the download API) can grab everything directly:

```
lsq pull                  # finds whoever is sharing
lsq pull "Kitchen Pi"     # or name the peer
lsq pull 192.168.1.7      # or its address
```

The share link is plain HTTP, because browsers refuse the self-signed
certificates LocalSend devices use. Add `--pin` if the network isn't all
yours.

By default lsq uses port 53317, the same as the LocalSend app. To run it on a
machine where the app is already running, give its server another port:

```
lsq receive --port 53318 --dest ~/Downloads
```

Discovery still happens on the standard port, so peers find it either way.

`lsq --help` and `lsq <command> --help` list the rest of the flags.

## Identity

lsq keeps a self-signed certificate in `~/.config/lsq` (change it with
`LSQ_CONFIG_DIR`). Its fingerprint is how other devices recognise the same
machine across runs. Use `--ephemeral` for a throwaway identity instead.

## PIN

To require a code before a transfer is accepted:

```
lsq receive --pin 123456
lsq send file.txt --to laptop --pin 123456
lsq share file.txt --pin 123456
```

Wrong guesses are rate-limited per IP, the same way the app does it. On a
shared link the browser shows a PIN form; `lsq pull` takes `--pin`.

## What works and what doesn't

It implements LocalSend protocol v2.1: multicast discovery, the upload API in
both directions, the download API (`share`/`pull`, including the browser
page), PIN, and cancel. I've run the upload path against the desktop app
(v1.17.0) both ways, with single and multiple files and with a PIN set, and
files come across intact.

Still missing:

- IPv6
- anything newer than protocol v2.1

## Tests

```
cargo test
```

The integration tests start a real receiver and hit it with real HTTP clients,
including the annoying cases: partial uploads, hostile filenames, wrong tokens,
cancel mid-transfer, size overruns.

## License

Apache-2.0.
