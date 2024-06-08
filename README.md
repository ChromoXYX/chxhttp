# chxhttp

A HTTP/1.1 and HTTP/2 server based on [chxnet](https://github.com/ChromoXYX/chxnet)

Currently under development.

## Requirements

- kernel version 5.19 or higher, with ktls enabled.

## Build Requirements

- gcc version 12.1 or higher.
- dependencies of [chxnet](https://github.com/ChromoXYX/chxnet) and [chxlog](https://github.com/ChromoXYX/chxlog)
- openssl version 3.0 or higher for TLS
- [llhttp](https://github.com/nodejs/llhttp) for HTTP/1.1
- [boost](https://www.boost.org/) version 1.75.0 or higher for program options and json parsing

## Build

```bash
git clone --recurse-submodules https://github.com/ChromoXYX/chxhttp.git
autoreconf -iv
./configure
# read ./configure --help for details
make
```

## Configuration

chxhttp uses json for configuration. Refer to config.json and conf.d/test.json for exmaples.
