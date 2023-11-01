module my_first_package::my_module {
    use sui::tx_context::{Self, TxContext};
    use sui::hash;
    use sui::ecdsa_k1;
    use std::debug;
    use std::vector;
    use std::bcs;

    // compute roothash for KYC PublicVC
    fun compute_roothash(value_u256: u256, value_vec_1: vector<u8>, value_vec_2: vector<u8>): vector<u8>{
        let hash_1 = hash::keccak256(&keccak256_u256(value_u256));
        let hash_2 = hash::keccak256(&keccak256_vector(value_vec_1));
        let hash_3 = hash::keccak256(&keccak256_vector(value_vec_2));

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

    fun pack_u256(value_to_pack: u256) : vector<u8> {
        let value_vector = bcs::to_bytes(&value_to_pack);
        std::vector::reverse(&mut value_vector);
        value_vector
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
    fun init(_ctx: &mut TxContext) {
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

    #[test]
    fun test_hash_result() {
        use sui::test_scenario;

        // create test addresses representing users
        let admin = @0xBABE;

        // first transaction to emulate module initialization
        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        let holder_addr = vector<u8>[0x11, 0xf8, 0xb7, 0x7F, 0x34, 0xFC, 0xF1, 0x4B, 0x70, 0x95, 0xBF, 0x52, 0x28, 0xAc, 0x06, 0x06, 0x32, 0x4E, 0x82, 0xD1];
        let issuanceDate =  vector<u8>[0x01, 0x8b, 0x6a, 0xe3, 0x73, 0xdc];
        let expirationDate = vector<u8>[0x00];
        let ctypeHash = vector<u8>[0xd3,0x15, 0x23, 0xb3, 0xce, 0x50, 0x6c, 0xce, 0xff, 0xa8, 0xe9, 0x87, 0xe4, 0xc7, 0xa2, 0x12, 0x99, 0xe9, 0x3c, 0x4f, 0x28, 0x61, 0x4d, 0x5d, 0xa7, 0xd1, 0x02, 0x6e, 0x6c, 0xf3, 0x49, 0x0b];
        
        let signature = vector<u8>[0x54, 0x47, 0xc6, 0xe5, 0x47, 0x37, 0x92, 0x20, 0xea, 0x89, 0x4e, 0xaa, 0xec, 0x61, 0xc6, 0xb8, 0xe1, 0x10, 0x0b, 0x61, 0x06, 0x80, 0xeb, 0x66, 0x96, 0x67, 0x6d, 0x28, 0xe1, 0x39, 0xff, 0xea, 0x7a, 0x6c, 0xc3, 0xcb, 0x26, 0x63, 0xc0, 0x9d, 0xcd, 0xd1, 0x7e, 0xc9, 0x0b, 0xca, 0x94, 0x83, 0x50, 0xf4, 0x38, 0x52, 0xeb, 0xbd, 0xc5, 0x5c, 0x63, 0xd6, 0xa7, 0x67, 0x0d, 0xf0, 0xdb, 0x93, 0x01];
        
        {
            init(test_scenario::ctx(scenario));
        };
        // second transaction executed by admin to create the sword
        test_scenario::next_tx(scenario, admin);
        {
            //  ===========  OK!! calculate ROOTHASH =================
            let roothash = compute_roothash(1, b"eth", b"0x05476EE9235335ADd2e50c09B2D16a3A2cC4ebEC");

            //  ===========  OK!! calculate DIGEST =================
            let digest = compute_digest(roothash, holder_addr, issuanceDate, expirationDate, ctypeHash);
            debug::print(&digest);

            // ========= construct EIP191 sign ===============
            let ethSignedMessage = pad_signed_message(digest);
            let verification_result = erecover_to_eth_address(signature, ethSignedMessage);

            debug::print(&verification_result);
        };
        test_scenario::end(scenario_val);
    }
}


