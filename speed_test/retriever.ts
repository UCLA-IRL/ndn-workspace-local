import { Endpoint } from '@ndn/endpoint';
import { digestSigning, Name } from '@ndn/packet';
import { FwTracer } from '@ndn/fw';
import { UnixTransport } from '@ndn/node-transport';
import { SequenceNum } from '@ndn/naming-convention2';
import * as nfdmgmt from '@ndn/nfdmgmt';
import { AsyncDisposableStack } from '@ucla-irl/ndnts-aux/utils';
import { InMemoryStorage } from '@ucla-irl/ndnts-aux/storage';
import { AtLeastOnceDelivery } from '@ucla-irl/ndnts-aux/sync-agent';

// Global configurations
const DEBUG = false;
// const MAX_SEQUENCE = 100;
const WORKSPACE_NAME = new Name('/ndn-test/workspace');

const registerPrefixes = async (endpoint: Endpoint, workspaceName: Name, nodeId: Name) => {
  // Register prefixes
  const cr = await nfdmgmt.invoke('rib/register', {
    name: workspaceName,
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    endpoint: endpoint,
    prefix: nfdmgmt.localhostPrefix,
    signer: digestSigning,
  });
  if (cr.statusCode !== 200) {
    console.error(`Unable to register route: ${cr.statusCode} ${cr.statusText}`);
    Deno.exit();
  }
  const cr2 = await nfdmgmt.invoke('rib/register', {
    name: nodeId,
    origin: 65, // client
    cost: 0,
    flags: 0x02, // CAPTURE
  }, {
    endpoint: endpoint,
    prefix: nfdmgmt.localhostPrefix,
    signer: digestSigning,
  });
  if (cr2.statusCode !== 200) {
    console.error(`Unable to register route: ${cr2.statusCode} ${cr2.statusText}`);
    Deno.exit();
  }
};

const main = async () => {
  await using closers = new AsyncDisposableStack();

  // Connect to local NFD
  const endpoint = new Endpoint();
  const face = await UnixTransport.createFace({ l3: { local: true } }, '/run/nfd/nfd.sock');
  closers.defer(() => face.close());

  // Register prefixes
  const nodeId = WORKSPACE_NAME.append('node-r');
  await registerPrefixes(endpoint, WORKSPACE_NAME, nodeId);

  // Exiter
  const { resolve: exitResolve, promise: exitSignal } = Promise.withResolvers<void>();

  // Alo
  let baseTime: number;
  const storage = new InMemoryStorage();
  closers.use(storage);
  const alo = await AtLeastOnceDelivery.create(
    nodeId,
    endpoint,
    WORKSPACE_NAME.append('32=sync', '32=alo'),
    digestSigning,
    digestSigning,
    storage,
    Promise.resolve((content: Uint8Array, id: Name) => {
      if (!baseTime) {
        baseTime = Date.now();
      }
      console.log(
        Date.now() - baseTime,
        id.toString(),
        new TextDecoder().decode(content),
      );
      return Promise.resolve();
    }),
  );
  closers.use(alo);

  alo.onReset = exitResolve;
  alo.start();
  await alo.produce(new Uint8Array());

  await exitSignal;
};

if (import.meta.main) {
  if (DEBUG) FwTracer.enable();
  await main();
}
