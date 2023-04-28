import type { HexString } from '@zcloak/crypto/types';
import type { DidUrl } from '@zcloak/did-resolver/types';
import { calcDigest, DigestPayload } from '@zcloak/vc';
import { VerifiableCredentialVersion } from '@zcloak/vc/types';

export function caclculateDigest(
    roothash: HexString,
    user_did: DidUrl,
    issuanceDate: number,
    expirationDate: number,
    ctype: HexString,
    vc_version: VerifiableCredentialVersion
): HexString {
    let digest_payload: any;
    if (vc_version == '1') {
        digest_payload = {
            rootHash: roothash,
            holder: user_did,
            issuanceDate: issuanceDate,
            expirationDate: expirationDate,
            ctype: ctype
        }
    } else {
        digest_payload = {
            rootHash: roothash,
            holder: user_did,
            expirationDate: expirationDate,
            ctype: ctype
        }
    }

    const digest = calcDigest(vc_version, digest_payload as DigestPayload<typeof vc_version>);
    return digest.digest;
}