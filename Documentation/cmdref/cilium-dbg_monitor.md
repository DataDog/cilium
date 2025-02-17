<!-- This file was autogenerated via cilium-dbg cmdref, do not edit manually-->

## cilium-dbg monitor

Display BPF program events

### Synopsis

The monitor displays notifications and events emitted by the BPF
programs attached to endpoints and devices. This includes:
  * Dropped packet notifications
  * Captured packet traces
  * Policy verdict notifications
  * Debugging information

```
cilium-dbg monitor [flags]
```

### Options

```
      --from []uint16           Filter by source endpoint id
  -h, --help                    help for monitor
      --hex                     Do not dissect, print payload in HEX
  -j, --json                    Enable json output. Shadows -v flag
      --monitor-socket string   Configure monitor socket path
  -n, --numeric                 Display all security identities as numeric values
      --related-to []uint16     Filter by either source or destination endpoint id
      --to []uint16             Filter by destination endpoint id
  -t, --type []string           Filter by event types [agent capture debug drop l7 policy-verdict recorder trace trace-sock]
  -v, --verbose bools[=false]   Enable verbose output (-v, -vv) (default [])
```

### Options inherited from parent commands

```
      --config string        Config file (default is $HOME/.cilium.yaml)
  -D, --debug                Enable debug messages
  -H, --host string          URI to server-side API
      --log-driver strings   Logging endpoints to use (example: syslog)
      --log-opt map          Log driver options (example: format=json)
```

### SEE ALSO

* [cilium-dbg](cilium-dbg.md)	 - CLI

