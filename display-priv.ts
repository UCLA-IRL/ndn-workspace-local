import { base64ToBytes, bytesToBase64 } from '@ucla-irl/ndnts-aux/utils';
import { Decoder, Encoder } from '@ndn/tlv';
import { SafeBag } from '@ndn/ndnsec';

if (import.meta.main) {
  if (Deno.args.length < 1 || !Deno.args[0]) {
    console.error('Please input the passcode');
    Deno.exit(1);
  }

  const decoder = new TextDecoder();
  for await (const chunk of Deno.stdin.readable) {
      const b64Value = decoder.decode(chunk);
      const passcode = Deno.args[0];
      const wire = base64ToBytes(b64Value);
      const safebag = Decoder.decode(wire, SafeBag);
      const cert = safebag.certificate;
      const prvKey = await safebag.decryptKey(passcode);
      console.log('CERTIFICATE:  ', bytesToBase64(Encoder.encode(cert.data)));
      console.log('PRIVATE KEY:  ', bytesToBase64(prvKey));
  }
}
