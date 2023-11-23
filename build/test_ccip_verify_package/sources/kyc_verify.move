module test_ccip_verify_package::kyc_verify {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::vec_set::{Self, VecSet};

    use sui::hash;
    use sui::ecdsa_k1;
    use std::vector;
    use sui::bcs;
    use std::string::{Self};
    use sui::address;
    use sui::clock::{Self, Clock};
    use sui::ed25519;
    use sui::transfer;

    struct AdminCap has key {
        id: UID
    }

    struct AttesterWhiteList has key {
        id: UID,
        attesterWhiteList: VecSet<vector<u8>>
    }
    public fun attester_exist(
        attester_to_query: vector<u8>,
        attesterList: &AttesterWhiteList
    ): bool {
        vec_set::contains(&attesterList.attesterWhiteList, &attester_to_query)
    }

    public fun set_whitelist(
        _: &AdminCap,
        attesterList: vector<u8>,
        ctx: &mut TxContext,
        ){
        let m = vec_set::empty();
        vec_set::insert(&mut m, attesterList);

        transfer::transfer(AttesterWhiteList {
            id: object::new(ctx),
            attesterWhiteList: m
        }, tx_context::sender(ctx))
    }

    public fun modify_remove_whitelist(
        _: &AdminCap,
        attesterWhiteList: &mut AttesterWhiteList,
        attesterList: vector<u8>,
        ){
        let m = attesterWhiteList.attesterWhiteList;
        vec_set::remove(&mut m, &attesterList);

        attesterWhiteList.attesterWhiteList = m;
    }

    public fun modify_add_whitelist(
        _: &AdminCap,
        attesterWhiteList: &mut AttesterWhiteList,
        attesterList: vector<u8>,
        ){
        let m = attesterWhiteList.attesterWhiteList;
        vec_set::insert(&mut m, attesterList);
        attesterWhiteList.attesterWhiteList = m;
    }


    entry public fun verify_KYC(
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
    ) : u256 {
        // Only the vc is valid, return the digest
        let digest = verify_VC(
            value_kyc_status,
            holderAddr, 
            issuanceDate, 
            expirationDate, 
            ctypeHash,
            signature,
            attesterList,
            onChainAddr);
        
        let current_time = clock::timestamp_ms(clock);

        // If the vc's is already expired, abort with ErrorCode `42`
        assert!(bytes_to_u64(expirationDate) == 0 || bytes_to_u64(expirationDate) > current_time, 42);

        let verifyResult = verifyCCIPSignature(digest, timestamp, verifierSig, current_time);

        // If the CCIP Signature is not valid, abort with ErrorCode `44`
        assert!(verifyResult, 44);
        value_kyc_status
    }

    public fun verify_VC(
        value_kyc_status: u256,
        // the DID address
        holderAddr: vector<u8>, 
        issuanceDate: vector<u8>, 
        expirationDate: vector<u8>, 
        ctypeHash: vector<u8>,
        signature: vector<u8>,
        attesterWhiteList: &AttesterWhiteList,
        onChainAddr: address
    ) : vector<u8> {
        let bfcPrefix = b"bfc";
        let roothash = compute_roothash(value_kyc_status, bfcPrefix, onChainAddr);

        //  ===========  OK!! calculate DIGEST =================
        let digest = compute_digest(roothash, holderAddr, issuanceDate, expirationDate, ctypeHash);

        // ========= construct EIP191 sign ===============
        let ethSignedMessage = pad_signed_message(digest);
        let verificationResult = erecover_to_eth_address(signature, ethSignedMessage);

        // If the assertionMethod is not in the attester whitelist, abort with ErrorCode `41`
        assert!(attester_exist(verificationResult, attesterWhiteList), 41);
       
        digest

    }

    // compute roothash for KYC PublicVC
    fun compute_roothash(value_u256: u256, value_vec_1: vector<u8>, value_vec_2: address): vector<u8>{
        let hash_1 = hash::keccak256(&keccak256_u256(value_u256));
        let hash_2 = hash::keccak256(&keccak256_vector(value_vec_1));
        let hash_3 = hash::keccak256(&keccak256_address(value_vec_2));

        let parent_vec = std::vector::empty<u8>(); 
        vector::append(&mut parent_vec, hash_1);
        vector::append(&mut parent_vec, hash_2);
        let parent_hash = hash::keccak256(&parent_vec);

        let root_vec = std::vector::empty<u8>(); 
        vector::append(&mut root_vec, parent_hash);
        vector::append(&mut root_vec, hash_3);
        let roothash = hash::keccak256(&root_vec);
        roothash
    }

    fun verifyCCIPSignature(
        digest: vector<u8>, 
        timestamp: u64, 
        signature: vector<u8>,
        currentTimestamp: u64
    ): bool{
        assert!(currentTimestamp <= timestamp + 1000 * 60 * 5, 43);
        let networkU8a = b"bfc";
        let timestampU8a = pack_u64(timestamp);
        let concatU8a = std::vector::empty<u8>(); 

        vector::append(&mut concatU8a, digest);
        vector::append(&mut concatU8a, networkU8a);
        vector::append(&mut concatU8a, timestampU8a);

        // The publicKey of the server verifier(ed25519)
        let pk = vector<u8>[0x77, 0xc0, 0x72, 0xb8, 0xa3, 0x84, 0xfd, 0x28, 0x02, 0x45, 0xad, 0x7b, 0xff, 0x75, 0x7f, 0x26, 0xa2, 0x7d, 0x1f, 0x6e, 0x9a, 0x14, 0x13, 0xdb, 0x67, 0xae, 0x22, 0x7c, 0x97, 0xd4, 0x46, 0x9c];
       
        let hashedMessage = std::hash::sha2_256(concatU8a);

        let verify = ed25519::ed25519_verify(&signature, &pk, &hashedMessage);
        verify
    }

    // compute digest for KYC PublicVC
    fun compute_digest(roothash: vector<u8>, holder_addr: vector<u8>, issuanceDate: vector<u8>, expirationDate: vector<u8>, ctypeHash: vector<u8>): vector<u8>{
        let digest_concat = std::vector::empty<u8>(); 
        let did_zk_prefix = b"did:zk:";

        vector::append(&mut digest_concat, roothash);
        vector::append(&mut digest_concat, did_zk_prefix);
        vector::append(&mut digest_concat, holder_addr);
        vector::append(&mut digest_concat, issuanceDate);
        vector::append(&mut digest_concat, expirationDate);
        vector::append(&mut digest_concat, ctypeHash);
        
        let digest = hash::keccak256(&digest_concat);
        digest
    }

    fun pad_signed_message(digest: vector<u8>): vector<u8> {
        let ethSignedMessage = std::vector::empty<u8>(); 
        let prefix = b"\x19Ethereum Signed Message:\n32";
        vector::append(&mut ethSignedMessage, prefix);
        vector::append(&mut ethSignedMessage, digest);
        ethSignedMessage
    }

    fun pack_u64(value_to_pack: u64) : vector<u8> {
        let value_vector = bcs::to_bytes(&value_to_pack);
        std::vector::reverse(&mut value_vector);
        value_vector
    }

    fun pack_u256(value_to_pack: u256) : vector<u8> {
        let value_vector = bcs::to_bytes(&value_to_pack);
        std::vector::reverse(&mut value_vector);
        value_vector
    }

        // Helper -- convert sui addr to hashed result (single hash)
    fun keccak256_address(addr: address): vector<u8> {
        // let addressString = address::to_string(tx_context::sender(ctx));
        let addressString = address::to_string(addr);

        let concat = string::utf8(vector::empty());
        let prefix = string::utf8(b"0x");
        string::append(&mut concat, prefix);
        string::append(&mut concat, addressString);

        let address_u8 = bcs::to_bytes(&concat);
        std::vector::reverse(&mut address_u8);
        std::vector::pop_back(&mut address_u8);
        std::vector::reverse(&mut address_u8);


        let hash = hash::keccak256(&address_u8);

        hash
    }

    // Helper -- compute keccak256 for u256
    fun keccak256_u256(value: u256): vector<u8> {
        let pack_status = std::vector::empty<u8>(); 
        std::vector::append(&mut pack_status, pack_u256(value));
        // pack_status
        let hash = hash::keccak256(&pack_status);
        hash
    }

    // Helper -- compute keccak256 for vector & string
    fun keccak256_vector(value: vector<u8>): vector<u8> {
        let pack_status = std::vector::empty<u8>(); 
        std::vector::append(&mut pack_status, value);
        // pack_status
        let hash = hash::keccak256(&pack_status);
        hash
    }

    // Init: Module initializer to be executed when this module is published
    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap {
            id: object::new(ctx)
        }, tx_context::sender(ctx))
    }

    // Helper -- Recovers and returns the signing address
    fun erecover_to_eth_address(signature: vector<u8>, raw_msg: vector<u8>) : vector<u8> {
        let v = vector::borrow_mut(&mut signature, 64);
        if (*v == 27) {
            *v = 0;
        } else if (*v == 28) {
            *v = 1;
        } else if (*v > 35) {
            *v = (*v - 1) % 2;
        };

        let pubkey = ecdsa_k1::secp256k1_ecrecover(&signature, &raw_msg, 0);
        let uncompressed = ecdsa_k1::decompress_pubkey(&pubkey);


        // Take the last 64 bytes of the uncompressed pubkey.
        let uncompressed_64 = vector::empty<u8>();
        let i = 1;
        while (i < 65) {
            let value = vector::borrow(&uncompressed, i);
            vector::push_back(&mut uncompressed_64, *value);
            i = i + 1;
        };

        // Take the last 20 bytes of the hash of the 64-bytes uncompressed pubkey.
        let hashed = hash::keccak256(&uncompressed_64);
        let addr = vector::empty<u8>();
        let i = 12;
        while (i < 32) {
            let value = vector::borrow(&hashed, i);
            vector::push_back(&mut addr, *value);
            i = i + 1;
        };

        (addr)
    }

    public fun bytes_to_u64(bytes: vector<u8>): u64 {
        let value = 0u64;
        let i = 0u64;
        // std::vector::reverse(&mut bytes);

        let length = vector::length(&bytes);
        while (i < length) {
            value = value | ((*vector::borrow(&bytes, i) as u64) << ((8 * (length - 1 - i)) as u8));
            i = i + 1;
        };
        return value
    }

    #[test]
    fun test_hash_result() {
        use sui::test_scenario;
        use std::debug;

        // create test addresses representing users
        let admin = @0x8fb8eff69462aad4c20884c2cd4b7df33e6eb7cb5eba96319f17ea90ece45ded;

        // Set Some Paras
        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        let holder_addr = vector<u8>[0x11, 0xf8, 0xb7, 0x7F, 0x34, 0xFC, 0xF1, 0x4B, 0x70, 0x95, 0xBF, 0x52, 0x28, 0xAc, 0x06, 0x06, 0x32, 0x4E, 0x82, 0xD1];
        let issuanceDate =  vector<u8>[0x01, 0x8b, 0xd6, 0xea, 0x68, 0x39];
        let expirationDate = vector<u8>[0x00];
        let ctypeHash = vector<u8>[0xd3, 0x15, 0x23, 0xb3, 0xce, 0x50, 0x6c, 0xce, 0xff, 0xa8, 0xe9, 0x87, 0xe4, 0xc7, 0xa2, 0x12, 0x99, 0xe9, 0x3c, 0x4f, 0x28, 0x61, 0x4d, 0x5d, 0xa7, 0xd1, 0x02, 0x6e, 0x6c, 0xf3, 0x49, 0x0b];
        
        let signature = vector<u8>[0xbf, 0xe5, 0xe2, 0x01, 0x36, 0x84, 0x9f, 0x8a, 0x85, 0xbe, 0x94, 0x7e, 0xfd, 0x7f, 0xa5, 0xc9, 0x51, 0x9b, 0xb6, 0x2b, 0x3f, 0xc8, 0x36, 0xeb, 0xa2, 0x3a, 0xa9, 0xd4, 0x83, 0xbc, 0x3a, 0x89, 0x28, 0x23, 0x75, 0x5d, 0xcd, 0x50, 0xd0, 0xf4, 0x9d, 0x0b, 0xb7, 0x0b, 0x69, 0xa3, 0x8b, 0x8f, 0x29, 0xbd, 0xb2, 0xd6, 0x86, 0x98, 0x5e, 0xb9, 0x5a, 0x79, 0x66, 0x93, 0x72, 0x86, 0x0b, 0x83, 0x00];
        
        let assertionMethod = vector<u8>[0x9e,0xf8,0x8b,0x87,0x49,0xb7,0xe5,0xa0,0xe2,0xde,0xa5,0xdd,0x10,0xc9,0x93,0x95,0x65,0xd2,0xd2,0x15];
        {
            init(test_scenario::ctx(scenario));
        };

        // Add new whitelist attester
        test_scenario::next_tx(scenario, admin);
        {
            let adminCap = test_scenario::take_from_sender<AdminCap>(scenario);

            set_whitelist(&adminCap, assertionMethod, test_scenario::ctx(scenario));
            test_scenario::return_to_sender(scenario, adminCap);

        };
        test_scenario::next_tx(scenario, admin);
        {
            let whitelist = test_scenario::take_from_sender<AttesterWhiteList>(scenario);

            //  ===========  OK!! calculate ROOTHASH =================
            let roothash = compute_roothash(1, b"bfc", admin);

            //  ===========  OK!! calculate DIGEST =================
            let digest = compute_digest(roothash, holder_addr, issuanceDate, expirationDate, ctypeHash);
            debug::print(&digest);

            // ========= construct EIP191 sign ===============
            let ethSignedMessage = pad_signed_message(digest);
            let verification_result = erecover_to_eth_address(signature, ethSignedMessage);

            debug::print(&verification_result);
            let clock = clock::create_for_testing(test_scenario::ctx(scenario));

            let a = verify_VC(
                1,
                holder_addr,
                issuanceDate,
                vector<u8>[0x00],
                ctypeHash,
                signature,
                &whitelist,
                admin,
            );
            debug::print(&a);
        
            let sig = vector<u8>[23,  80, 135, 243, 140, 252, 181, 223, 183, 209, 106, 192,  49,  98, 103, 224, 153,  28,  74, 169, 102, 144, 233, 114,  16, 232, 217, 241, 247, 211,  64,  73, 142, 2,  20,  62, 116, 162, 196,  98, 241, 214,  41,  93, 144, 180, 162, 192, 120,  26, 192, 162,  33, 135, 182, 90,  96,  78, 247, 252,  55, 145, 192, 6];

            let verifyResult = verifyCCIPSignature(digest, 1700714355000, sig, 1700712764002);

            debug::print(&verifyResult);

            let kyc_verify = verify_KYC(
                1,
                admin,
                holder_addr,
                issuanceDate,
                vector<u8>[0x00],
                ctypeHash,
                signature,
                1700714355000,
                sig,
                &clock,
                &whitelist
                );

            debug::print(&kyc_verify);
            clock::destroy_for_testing(clock);
            test_scenario::return_to_sender(scenario, whitelist);
        };
        test_scenario::end(scenario_val);
    }
}