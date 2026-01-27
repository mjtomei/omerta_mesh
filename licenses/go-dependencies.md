# Go Dependencies

The `OmertaTunnel` module includes a userspace TCP/IP stack compiled as `libnetstack.a`.
This static library contains the following Go dependencies:

## Direct Dependencies

| Package | License | Source |
|---------|---------|--------|
| [gvisor.dev/gvisor](https://pkg.go.dev/gvisor.dev/gvisor) | [Apache-2.0](https://github.com/google/gvisor/blob/master/LICENSE) | https://github.com/google/gvisor |

## Indirect Dependencies

| Package | License | Source |
|---------|---------|--------|
| [github.com/google/btree](https://pkg.go.dev/github.com/google/btree) | [Apache-2.0](https://github.com/google/btree/blob/master/LICENSE) | https://github.com/google/btree |
| [golang.org/x/exp](https://pkg.go.dev/golang.org/x/exp) | [BSD-3-Clause](https://cs.opensource.google/go/x/exp/+/master:LICENSE) | https://cs.opensource.google/go/x/exp |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | [BSD-3-Clause](https://cs.opensource.google/go/x/sys/+/master:LICENSE) | https://cs.opensource.google/go/x/sys |
| [golang.org/x/time](https://pkg.go.dev/golang.org/x/time) | [BSD-3-Clause](https://cs.opensource.google/go/x/time/+/master:LICENSE) | https://cs.opensource.google/go/x/time |

---

## gVisor License (Apache-2.0)

```
Copyright 2018 The gVisor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

gVisor is a project by Google that provides a userspace kernel and container runtime.
OmertaMesh uses gVisor's netstack package to provide a userspace TCP/IP stack for
tunneling network traffic over mesh connections.

For the full Apache 2.0 license text, see: https://www.apache.org/licenses/LICENSE-2.0
