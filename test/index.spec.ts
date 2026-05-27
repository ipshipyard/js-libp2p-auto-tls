import { ed25519Crypto } from '@ipshipyard/crypto'
import { TypedEventEmitter, start, stop } from '@libp2p/interface'
import { peerIdFromString } from '@libp2p/peer-id'
import { multiaddr } from '@multiformats/multiaddr'
import { expect } from 'aegir/chai'
import { defaultLogger } from 'birnam'
import { MemoryDatastore } from 'datastore-core'
import delay from 'delay'
import { Key } from 'interface-datastore'
import { base58btc } from 'multiformats/bases/base58'
import { pEvent } from 'p-event'
import Sinon from 'sinon'
import { stubInterface } from 'sinon-ts'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { AutoTLS } from '../src/auto-tls.ts'
import { DEFAULT_CERTIFICATE_DATASTORE_KEY, DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME } from '../src/constants.ts'
import { importFromPem } from '../src/utils.ts'
import { CERT, CERT_FOR_OTHER_KEY, EXPIRED_CERT, INVALID_CERT, PRIVATE_KEY_PEM } from './fixtures/cert.ts'
import type { PrivateKey } from '@ipshipyard/crypto'
import type { Keychain } from '@ipshipyard/keychain'
import type { HTTP } from '@libp2p/http'
import type { ComponentLogger, Libp2pEvents, NodeInfo, Peer, PeerId, TypedEventTarget } from '@libp2p/interface'
import type { AddressManager, NodeAddress } from '@libp2p/interface-internal'
import type { Datastore } from 'interface-datastore'
import type { StubbedInstance } from 'sinon-ts'

interface StubbedAutoTLSComponents {
  peerId: PeerId
  logger: ComponentLogger
  addressManager: StubbedInstance<AddressManager>
  events: TypedEventTarget<Libp2pEvents>
  keychain: StubbedInstance<Keychain>
  datastore: Datastore
  nodeInfo: NodeInfo
  http: HTTP
}

describe('auto-tls', () => {
  let autoTLS: AutoTLS
  let components: StubbedAutoTLSComponents
  let certificateKey: PrivateKey

  beforeEach(async () => {
    const privateKey = await ed25519Crypto().generatePrivateKey()
    certificateKey = await importFromPem(PRIVATE_KEY_PEM)

    components = {
      peerId: peerIdFromString(base58btc.encode(privateKey.publicKey.toMultihash().bytes).substring(1)),
      logger: defaultLogger(),
      addressManager: stubInterface<AddressManager>(),
      events: new TypedEventEmitter(),
      keychain: stubInterface<Keychain>(),
      datastore: new MemoryDatastore(),
      nodeInfo: {
        name: 'name',
        version: 'version',
        userAgent: 'userAgent'
      },
      http: stubInterface<HTTP>()
    }

    // a mixture of LAN and public addresses
    const addresses: NodeAddress[] = [{
      multiaddr: multiaddr(`/ip4/127.0.0.1/tcp/1235/p2p/${components.peerId}`),
      verified: true,
      expires: Infinity,
      type: 'transport'
    }, {
      multiaddr: multiaddr(`/ip4/192.168.0.100/tcp/1235/p2p/${components.peerId}`),
      verified: true,
      expires: Infinity,
      type: 'transport'
    }, {
      multiaddr: multiaddr(`/ip4/82.32.57.46/tcp/2345/p2p/${components.peerId}`),
      verified: true,
      expires: Infinity,
      type: 'ip-mapping'
    }]

    components.addressManager.getAddressesWithMetadata.returns(addresses)
    components.addressManager.getAddresses.returns(addresses.map(({ multiaddr }) => multiaddr))
  })

  afterEach(async () => {
    await stop(autoTLS)
  })

  it('should error with an invalid forge endpoint', () => {
    expect(() => {
      return new AutoTLS(components, {
        forgeEndpoint: 'not a valid url'
      })
    }).to.throw('Invalid URL')
  })

  it('should error with an invalid acme directory', () => {
    expect(() => {
      return new AutoTLS(components, {
        acmeDirectory: 'not a valid url'
      })
    }).to.throw('Invalid URL')
  })

  it('should provision a TLS certificate', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    const eventPromise = pEvent(components.events, 'certificate:provision')

    autoTLS.fetchAcmeCertificate = Sinon.stub().resolves(CERT)

    components.keychain.exportKey.withArgs(DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME).resolves(certificateKey)

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })

    const event = await eventPromise
    expect(event).to.have.nested.property('detail.cert', CERT)
    expect(autoTLS.fetchAcmeCertificate).to.have.property('called', true)
  })

  it('should reuse an existing TLS certificate', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    const eventPromise = pEvent(components.events, 'certificate:provision')

    autoTLS.fetchAcmeCertificate = Sinon.stub().rejects(new Error('Should not have provisioned new certificate'))

    components.keychain.exportKey.withArgs(DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME).resolves(certificateKey)

    await components.datastore.put(new Key(DEFAULT_CERTIFICATE_DATASTORE_KEY), uint8ArrayFromString(CERT))

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })

    const event = await eventPromise
    expect(event).to.have.nested.property('detail.cert', CERT)
    expect(autoTLS.fetchAcmeCertificate).to.have.property('called', false)
  })

  it('should provision a new TLS certificate when the existing one is corrupted', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    const eventPromise = pEvent(components.events, 'certificate:provision')

    autoTLS.fetchAcmeCertificate = Sinon.stub().resolves(CERT)

    components.keychain.exportKey.withArgs(DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME).resolves(certificateKey)

    await components.datastore.put(new Key(DEFAULT_CERTIFICATE_DATASTORE_KEY), uint8ArrayFromString(INVALID_CERT))

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })

    const event = await eventPromise
    expect(event).to.have.nested.property('detail.cert', CERT)
    expect(autoTLS.fetchAcmeCertificate).to.have.property('called', true)
  })

  it('should provision a new TLS certificate when the existing one has expired', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    const eventPromise = pEvent(components.events, 'certificate:provision')

    autoTLS.fetchAcmeCertificate = Sinon.stub().resolves(CERT)

    components.keychain.exportKey.withArgs(DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME).resolves(certificateKey)

    await components.datastore.put(new Key(DEFAULT_CERTIFICATE_DATASTORE_KEY), uint8ArrayFromString(EXPIRED_CERT))

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })

    const event = await eventPromise
    expect(event).to.have.nested.property('detail.cert', CERT)
    expect(autoTLS.fetchAcmeCertificate).to.have.property('called', true)
  })

  it('should provision a new TLS certificate when validation fails', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    const eventPromise = pEvent(components.events, 'certificate:provision')

    autoTLS.fetchAcmeCertificate = Sinon.stub().resolves(CERT)

    components.keychain.exportKey.withArgs(DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME).resolves(certificateKey)

    await components.datastore.put(new Key(DEFAULT_CERTIFICATE_DATASTORE_KEY), uint8ArrayFromString(CERT_FOR_OTHER_KEY))

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })

    const event = await eventPromise
    expect(event).to.have.nested.property('detail.cert', CERT)
    expect(autoTLS.fetchAcmeCertificate).to.have.property('called', true)
  })

  it('should not provision when there are no public addresses', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    // mixture of LAN and public addresses
    components.addressManager.getAddresses.returns([
      multiaddr(`/ip4/127.0.0.1/tcp/1235/p2p/${components.peerId}`),
      multiaddr(`/ip4/192.168.0.100/tcp/1235/p2p/${components.peerId}`)
    ])

    let dispatched = 0

    components.events.addEventListener('certificate:provision', () => {
      dispatched++
    })
    components.events.addEventListener('certificate:renew', () => {
      dispatched++
    })

    await delay(1000)

    expect(dispatched).to.equal(0)
  })

  it('should not provision when there are no supported addresses', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    // mixture of LAN and public addresses
    components.addressManager.getAddresses.returns([
      multiaddr(`/ip4/82.32.57.46/tcp/2345/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN/p2p-circuit/p2p/${components.peerId}`)
    ])

    let dispatched = 0

    components.events.addEventListener('certificate:provision', () => {
      dispatched++
    })
    components.events.addEventListener('certificate:renew', () => {
      dispatched++
    })

    await delay(1000)

    expect(dispatched).to.equal(0)
  })

  it('should remap domain names when the external IP address changes', async () => {
    autoTLS = new AutoTLS(components, {
      provisionDelay: 10
    })
    await start(autoTLS)

    const eventPromise = pEvent(components.events, 'certificate:provision')

    autoTLS.fetchAcmeCertificate = Sinon.stub().resolves(CERT)

    components.keychain.exportKey.withArgs(DEFAULT_CERTIFICATE_PRIVATE_KEY_NAME).resolves(certificateKey)

    await components.datastore.put(new Key(DEFAULT_CERTIFICATE_DATASTORE_KEY), uint8ArrayFromString(CERT_FOR_OTHER_KEY))

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })

    const event = await eventPromise
    expect(event).to.have.nested.property('detail.cert', CERT)
    expect(autoTLS.fetchAcmeCertificate).to.have.property('called', true)

    // a different external address is reported
    components.addressManager.getAddresses.returns([
      multiaddr(`/ip4/127.0.0.1/tcp/1235/p2p/${components.peerId}`),
      multiaddr(`/ip4/192.168.0.100/tcp/1235/p2p/${components.peerId}`),
      multiaddr(`/ip4/64.23.65.25/tcp/2345/p2p/${components.peerId}`)
    ])

    components.events.safeDispatchEvent('self:peer:update', {
      detail: {
        peer: stubInterface<Peer>()
      }
    })
  })
})
