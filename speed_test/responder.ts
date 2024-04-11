import { produce } from '@ndn/endpoint';
import { SvSync } from '@ndn/svs';
import { Data, digestSigning, Interest, Name } from '@ndn/packet';
import { Forwarder, FwTracer } from '@ndn/fw';
import { UnixTransport } from '@ndn/node-transport';
import { SequenceNum } from '@ndn/naming-convention2';
import * as nfdmgmt from '@ndn/nfdmgmt';
import { AsyncDisposableStack } from '@ucla-irl/ndnts-aux/utils';

// Global configurations
const DEBUG = false;
const MAX_SEQUENCE = 100;
const WORKSPACE_NAME = new Name('/ndn-test/workspace');

const registerPrefixes = async (fw: Forwarder, workspaceName: Name, nodeId: Name) => {
  // Register prefixes
  const cr = await nfdmgmt.invoke('rib/register', {
    name: workspaceName,
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
    name: nodeId,
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
};

const main = async () => {
  await using closers = new AsyncDisposableStack();

  // Connect to local NFD
  const fw = Forwarder.getDefault();
  const face = await UnixTransport.createFace({ l3: { local: true } }, '/run/nfd/nfd.sock');
  closers.defer(() => face.close());

  // Register prefixes
  const nodeId = WORKSPACE_NAME.append('node-p');
  await registerPrefixes(fw, WORKSPACE_NAME, nodeId);

  // Create responder
  let baseTime: number;
  const dataNamePrefix = nodeId.append('32=sync', '32=alo');
  const producer = produce(
    dataNamePrefix,
    async (interest: Interest) => {
      await undefined;
      const seq = interest.name.at(interest.name.length - 1).as(SequenceNum) satisfies number;
      if (seq < MAX_SEQUENCE) {
        if (!baseTime) {
          baseTime = Date.now();
        }
        console.log('+', seq, Date.now() - baseTime, 'ms');
        return new Data(interest.name, new TextEncoder().encode(`${seq}`));
      } else {
        console.log('-', seq, Date.now() - baseTime, 'ms');
        return undefined;
      }
    },
    {
      announcement: dataNamePrefix,
      dataSigner: digestSigning,
    },
  );
  closers.defer(() => producer.close());

  // Create SvSync and produce
  const syncInst = await SvSync.create({
    syncPrefix: WORKSPACE_NAME.append('32=sync', '32=alo'),
    signer: digestSigning,
    steadyTimer: [1000, 10],
  });
  closers.defer(() => syncInst.close());
  syncInst.get(WORKSPACE_NAME.append('node-p')).seqNum = 100;

  const exitSignal = new Promise<void>((resolve) => {
    Deno.addSignalListener('SIGINT', () => {
      console.log('Stopped by Ctrl+C');
      resolve();
    });
  });
  await exitSignal;
};

if (import.meta.main) {
  if (DEBUG) FwTracer.enable();
  await main();
}
