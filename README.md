# @ipshipyard/libp2p-auto-tls

[![codecov](https://img.shields.io/codecov/c/github/ipshipyard/js-libp2p-auto-tls.svg?style=flat-square)](https://codecov.io/gh/ipshipyard/js-libp2p-auto-tls)
[![CI](https://img.shields.io/github/actions/workflow/status/ipshipyard/js-libp2p-auto-tls/js-test-and-release.yml?branch=main\&style=flat-square)](https://github.com/ipshipyard/js-libp2p-auto-tls/actions/workflows/js-test-and-release.yml?query=branch%3Amain)

> Automatically acquire a <peerId>.libp2p.direct TLS certificate

# About

<!--

!IMPORTANT!

Everything in this README between "# About" and "# Install" is automatically
generated and will be overwritten the next time the doc generator is run.

To make changes to this section, please update the @packageDocumentation section
of src/index.js or src/index.ts

To experiment with formatting, please run "npm run docs" from the root of this
repo and examine the changes made.

-->

When a publicly dialable address is detected, use the p2p-forge service at
<https://registration.libp2p.direct> to acquire a valid Let's Encrypt-backed
TLS certificate, which the node can then use with the relevant transports.

The node must be configured with a listener for at least one of the following
transports:

- TCP or WS or WSS, (along with the Yamux multiplexer and TLS or Noise encryption)
- QUIC-v1
- WebTransport

It also requires the Identify protocol.

## Example - Use UPnP to hole punch and auto-upgrade to Secure WebSockets

```TypeScript
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { autoTLS } from '@ipshipyard/libp2p-auto-tls'
import { identify } from '@libp2p/identify'
import { keychain } from '@libp2p/keychain'
import { webSockets } from '@libp2p/websockets'
import { uPnPNAT } from '@libp2p/upnp-nat'
import { createLibp2p } from 'libp2p'

const node = await createLibp2p({
  addresses: {
    listen: [
      '/ip4/0.0.0.0/tcp/0/ws'
    ]
  },
  transports: [
    webSockets()
  ],
  connectionEncrypters: [
    noise()
  ],
  streamMuxers: [
    yamux()
  ],
  services: {
    autoTLS: autoTLS(),
    identify: identify(),
    keychain: keychain(),
    upnp: uPnPNAT()
  }
})

// ...time passes

console.info(node.getMultiaddrs())
// includes public WSS address:
// [ '/ip4/123.123.123.123/tcp/12345/wss ]
```

# Install

```console
$ npm i @ipshipyard/libp2p-auto-tls
```

# License

Licensed under either of

- Apache 2.0, ([LICENSE-APACHE](https://github.com/ipshipyard/js-libp2p-auto-tls/LICENSE-APACHE) / <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT ([LICENSE-MIT](https://github.com/ipshipyard/js-libp2p-auto-tls/LICENSE-MIT) / <http://opensource.org/licenses/MIT>)

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
