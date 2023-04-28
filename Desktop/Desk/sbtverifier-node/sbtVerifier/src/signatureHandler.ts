import type { Keypair } from '@zcloak/crypto/types';
import { secp256k1Sign } from '@zcloak/crypto';
import { getMessage } from '@zcloak/crypto/eip712/eip712';
import type { DidUrl } from '@zcloak/did-resolver/types';
import type { HexString } from '@zcloak/crypto/types';
import type { VerifiableCredentialVersion } from '@zcloak/vc/types';
import { parseDid } from '@zcloak/did-resolver/parseDid'

export function eip712_sign(
    recipient: DidUrl,
    ctype: HexString,
    program_hash: string,
    digest: HexString,
    verifier: string,
    keypair: Keypair,
    attester: DidUrl,
    zkp_result: string,
    issuance_date: number,
    expiration_date: number,
    vc_version: VerifiableCredentialVersion,
    sbt_link: string,
): Uint8Array {
    let typedData = constrcut_typedData(recipient, ctype, program_hash, digest, attester, verifier, zkp_result, issuance_date, expiration_date, vc_version, sbt_link);
    const message = getMessage(typedData, true);

    const signature = secp256k1Sign(message, keypair);
    return signature;
}


function constrcut_typedData(
    recipient: DidUrl,
    ctype: HexString,
    programHash: string,
    digest: HexString,
    attester: DidUrl,
    verifier: string,
    zkp_result: string,
    issuance_date: number,
    expiration_date: number,
    vc_version: VerifiableCredentialVersion,
    sbt_link: string,
) {
    const recipient_address: string = parseDid(recipient).identifier;
    const attester_address: string = parseDid(attester).identifier;
    const verifier_address: string = verifier;
    const vc_bytes2 = vc_version == '1' ? '0x0001' : '0x0000';

    // todo: update the parse, JSON.parse might cause precise missing for uint64
    const outputs = JSON.parse(zkp_result).outputs.stack;

    const typedData = {
        types: {
            EIP712Domain: [
                { name: 'name', type: 'string' },
                { name: 'version', type: 'string' },
                { name: 'chainId', type: 'uint256' },
                { name: 'verifyingContract', type: 'address' }
            ],
            Signature: [
                { name: 'recipient', type: 'address' },
                { name: 'ctype', type: 'bytes32' },
                { name: 'programHash', type: 'bytes32' },
                { name: 'digest', type: 'bytes32' },
                { name: 'verifier', type: 'address' },
                { name: 'attester', type: 'address' },
                { name: 'output', type: 'uint64[]' },
                { name: 'issuanceTimestamp', type: 'uint64' },
                { name: 'expirationTimestamp', type: 'uint64' },
                { name: 'vcVersion', type: 'bytes2' },
                { name: 'sbtLink', type: 'string' },
            ]
        },
        primaryType: 'Signature',
        // change when the final contract is deployed
        domain: {
            name: 'zCloakSBT',
            version: '0',
            chainId: 4,
            verifyingContract: '0x6b7baf71cb9f4858325e76a4e8f085e9c54635b8'
        },
        message: {
            recipient: recipient_address,
            ctype: ctype,
            programHash: `0x${programHash}`,
            digest: digest,
            verifier: verifier_address,
            attester: attester_address,
            output: outputs,
            issuanceTimestamp: issuance_date,
            expirationTimestamp: expiration_date,
            vcVersion: vc_bytes2,
            sbtLink: sbt_link
        }
    }
    return typedData;
};