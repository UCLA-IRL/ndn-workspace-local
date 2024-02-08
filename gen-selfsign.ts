import { bytesToBase64 } from '@ucla-irl/ndnts-aux/utils';
import { Encoder } from '@ndn/tlv';
import { Name } from '@ndn/packet';
import { Certificate, CertNaming, createSigner, createVerifier, ECDSA } from '@ndn/keychain';

if (import.meta.main) {
  if (Deno.args.length < 1 || !Deno.args[0]) {
    console.error('Please input the identity name');
    Deno.exit(1);
  }

  // Generate key pair
  const idName = new Name(Deno.args[0]);
  const keyName = CertNaming.makeKeyName(idName);
  const algo = ECDSA;
  const gen = await ECDSA.cryptoGenerate({}, true);
  const privateKey = createSigner(keyName, algo, gen);
  const publicKey = createVerifier(keyName, algo, gen);
  const prvKeyBits = await crypto.subtle.exportKey('pkcs8', gen.privateKey);
  const cert = await Certificate.selfSign({ privateKey, publicKey });
  const certBits = Encoder.encode(cert.data);
  console.log('CERTIFICATE:  ', bytesToBase64(certBits));
  console.log('PRIVATE KEY:  ', bytesToBase64(new Uint8Array(prvKeyBits)));
}
