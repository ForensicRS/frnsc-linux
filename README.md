# frnsc-linux

Linux artifact parsers: utmp/wtmp/btmp/lastlog login records, journald, syslog and more

Part of the [ForensicRS](https://github.com/ForensicRS) ecosystem, built on
[`forensic-rs`](https://github.com/ForensicRS/forensic-rs).

## Development

This crate is meant to be developed inside the ForensicRS workspace
(`forensic-bootstrap`), which builds it against your local `forensic-rs` checkout:

```sh
cargo test -p frnsc-linux
../forensic-testenv/tools/fetch.py --crate frnsc-linux   # real-world samples for the integration tests
```

## Coverage and limitations

- `unix::utmp` — byte-level `utmp`/`wtmp`/`btmp` fixed-size record layout (both the 384-byte
  32-bit-compatible and the 400-byte genuine-64-bit on-disk layouts). Not yet wired into an
  `ArtifactParserFactory`: that needs an additive upstream `forensic-rs` change (a new
  `LinuxArtifacts::Utmp` variant and several `dictionary` ECS constants) that has not landed.
  See the workspace `FINDINGS.md` for the tracking issue. `lastlog`'s simpler fixed-size record
  is not covered yet.
- Everything else in the design (`journal`, `log`, `containers`, `shell`, `schedule`, `units`,
  `packages`, `identity`) is not started. See `docs/artifact-catalog-roadmap.md` and the linked
  design document for the phased plan.
