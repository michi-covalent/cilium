<!-- This file was autogenerated via cilium cmdref, do not edit manually-->

## cilium map get

Display cached content of given BPF map

```
cilium map get <name> [flags]
```

### Examples

```
cilium map get cilium_ipcache
```

### Options

```
  -h, --help            help for get
  -o, --output string   json| yaml| jsonpath='{}'
```

### Options inherited from parent commands

```
      --config string   Config file (default is $HOME/.cilium.yaml)
  -D, --debug           Enable debug messages
  -H, --host string     URI to server-side API
```

### SEE ALSO

* [cilium map](cilium_map.md)	 - Access userspace cached content of BPF maps
