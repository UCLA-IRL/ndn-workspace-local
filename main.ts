import { DenoKvStorage } from '@ucla-irl/ndnts-aux/storage';
import { Workspace } from '@ucla-irl/ndnts-aux/workspace';
import { AsyncDisposableStack, base64ToBytes } from '@ucla-irl/ndnts-aux/utils';
import { CertStorage } from '@ucla-irl/ndnts-aux/security';
import { Decoder } from '@ndn/tlv';
import { Data, digestSigning, Name } from '@ndn/packet';
import { Certificate } from '@ndn/keychain';
import { SafeBag } from '@ndn/ndnsec';
import { UnixTransport } from '@ndn/node-transport';
import * as nfdmgmt from '@ndn/nfdmgmt';
import { Forwarder, FwTracer } from '@ndn/fw';
import * as Y from 'yjs';

const TRUST_ANCHOR = `
Bv0BPQc0CA1uZG4td29ya3NwYWNlCAR0ZXN0CANLRVkICFJS7LZ8gfUFCARzZWxm
NggAAAGLZIrN/xQJGAECGQQANu6AFVswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATxuBAe/TYwLQ9e8Zt4cEXW1NPYAW3uooS+ZXTWeqLaXWF8Rlj4CzVzX8SPYiV8
peenggFj5b3qEuMiBPlDQblvFlUbAQMcJgckCA1uZG4td29ya3NwYWNlCAR0ZXN0
CANLRVkICFJS7LZ8gfUF/QD9Jv0A/g8yMDIzMTAyNVQwMTU1MDD9AP8PMjA0MzEw
MjBUMDE1NTAwF0YwRAIgRWW2rafR0vHSsA7uAeb78nSFUPxO0gAwl9KKMzJwuJgC
IEi9gc1gaM3/GYatfQUytQhvOnFxEEnWx+q4MxK7+Knh
`;

const SAFEBAG = `
gP0CSwb9AVYHPAgNbmRuLXdvcmtzcGFjZQgEdGVzdAgGbm9kZS0yCANLRVkICG0T
2mtJZDFWCARyb290NggAAAGLZJoxgRQJGAECGQQANu6AFVswWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATvyM+YO9/RWllBkDkr/Pu/TCZMiEDY6H7rkwoHhU267LdH
+XM4HgavvQcU7/kQx0SMPzFlKl1cBRHgami6C9+XFmUbAQMcNgc0CA1uZG4td29y
a3NwYWNlCAR0ZXN0CANLRVkICFJS7LZ8gfUFCARzZWxmNggAAAGLZIrN//0A/Sb9
AP4PMjAyMzEwMjVUMDIxMTQ5/QD/DzIwMjQxMDI0VDAyMTE0OBdHMEUCIC4AvX8F
Q19e+08fUvL6+UcLMhtcsbRlcX/VA4b+0uRxAiEAhEHYzYBBBNOCH7LelcwJ12f+
amtgBvXaTSAjmWA4CWuB7zCB7DBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQww
HAQIfAcyXQiSbSgCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAeVjub
zfiRo/JfPmnW0bS9BIGQ183XD0RmcyNdxMzJtXKiNY12ST1G2Em5DfYHtWueywdI
xIr0U+no8kchpCABShtoz9aqFb5TgEmbevYavyFbF5P3byqK36jELjuAvVaJAQRl
fnI+BXFXipCPj8vqDswoovUHn/rBMXsoaUHjNqZ2/4nIBlc5PWNcDhZywF4e/Wvz
wTeeVxSVnsyT6d8V2bTA
`;

const decodeCert = (b64Value: string) => {
  const wire = base64ToBytes(b64Value);
  const data = Decoder.decode(wire, Data);
  const cert = Certificate.fromData(data);
  return cert;
};

const decodeSafebag = async (b64Value: string, passcode: string) => {
  const wire = base64ToBytes(b64Value);
  const safebag = Decoder.decode(wire, SafeBag);
  const cert = safebag.certificate;
  const prvKey = await safebag.decryptKey(passcode);
  return { cert, prvKey };
};

const DEBUG = false;

const main = async () => {
  if (DEBUG) FwTracer.enable();

  await using closers = new AsyncDisposableStack();

  const trustAnchor = decodeCert(TRUST_ANCHOR);
  const { cert, prvKey } = await decodeSafebag(SAFEBAG, '123456');

  const fw = Forwarder.getDefault();
  const storage = await DenoKvStorage.create('./data/kv-store');
  closers.use(storage);
  const certStore = new CertStorage(trustAnchor, cert, storage, fw, prvKey);

  const face = await UnixTransport.createFace({ l3: { local: true } }, '/run/nfd/nfd.sock');
  closers.defer(() => face.close());
  // Not working. Registered wrong profixes (.../test/sync/alo)
  // enableNfdPrefixReg(face, {
  //   signer: digestSigning,
  // });
  // Register prefixes
  const cr = await nfdmgmt.invoke('rib/register', {
    name: new Name('/ndn-workspace/test'),
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    cOpts: { fw },
    prefix: nfdmgmt.localhostPrefix,
    signer: digestSigning,
  });
  if (cr.statusCode !== 200) {
    console.error(`Unable to register route: ${cr.statusCode} ${cr.statusText}`);
    Deno.exit();
  }
  const cr2 = await nfdmgmt.invoke('rib/register', {
    name: new Name('/ndn-workspace/test/node-2'),
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    cOpts: { fw },
    prefix: nfdmgmt.localhostPrefix,
    signer: digestSigning,
  });
  if (cr2.statusCode !== 200) {
    console.error(`Unable to register route: ${cr2.statusCode} ${cr2.statusText}`);
    Deno.exit();
  }

  // TODO: Run without a signer
  const workspace = await Workspace.create({
    nodeId: new Name('/ndn-workspace/test/node-2'),
    persistStore: storage,
    fw,
    rootDoc: new Y.Doc(),
    signer: certStore.signer,
    verifier: certStore.verifier,
  });
  closers.defer(() => workspace.destroy());

  const exitSignal = new Promise<void>((resolve) => {
    Deno.addSignalListener('SIGINT', () => {
      console.log('Stopped by Ctrl+C');
      resolve();
    });
  });
  await exitSignal;
};

if (import.meta.main) {
  await main();
}
