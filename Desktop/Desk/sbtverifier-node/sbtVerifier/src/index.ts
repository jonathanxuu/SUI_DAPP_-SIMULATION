import { helpers } from '@zcloak/did';
import { VerifiableCredentialBuilder } from '@zcloak/vc';

// == phase 0: ZKP Generated (Generated in zkID Wallet, send to Server To Verify)  =====

// ============= phase 1: ZKP send to the Rust Verifier ================================
// The Rust Verifier should verify whether the ZKP is valid, and return the roothash and security_level(u32)

// ========== phase 2: Restore the digest and check the attester's signature ===========


// ========== phase 3: Generate the SBT Picture and upload that on Arweave =============



// ========== phase 4: Verifier should make a signature for the whole process(text) ====
