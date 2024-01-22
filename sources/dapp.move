module dapp::dapp_module {
   use test_ccip_verify_package::kyc_verify::{verify_KYC, AttesterWhiteList};

   use sui::tx_context::{Self, TxContext};
   use sui::clock::{Self, Clock};
   use sui::object::{Self, UID};
   use sui::transfer;

   struct KYCRecord has key {
        id: UID,
        kycStatus: u256,
        timestamp: u64
    }

   entry public fun callz(
       value_kyc_status: u256,
        onChainAddr: address,
        // the DID address
        holderAddr: vector<u8>, 
        issuanceDate: vector<u8>, 
        expirationDate: vector<u8>, 
        ctypeHash: vector<u8>,
        signature: vector<u8>,
        timestamp: u64,
        verifierSig: vector<u8>,
        clock: &Clock,
        attesterList: &AttesterWhiteList,

        ctx: &mut TxContext
    ) {
      verify_KYC(
         value_kyc_status,
         onChainAddr,
         holderAddr,
         issuanceDate, 
         expirationDate, 
         ctypeHash,
         signature,
         timestamp,
         verifierSig,
         clock,
         attesterList
        );
         
      let current_time = clock::timestamp_ms(clock);

      transfer::transfer(KYCRecord {
            id: object::new(ctx),
            kycStatus: value_kyc_status,
            timestamp: current_time
        }, onChainAddr)
    }
}



