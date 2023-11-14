import { requestSuiFromFaucetV0, getFaucetHost } from '@benfen/bfc.js/faucet';
import { SuiClient, getFullnodeUrl } from '@benfen/bfc.js/client';
import { Ed25519Keypair } from '@benfen/bfc.js/keypairs/ed25519';
import { TransactionBlock } from '@benfen/bfc.js/transactions';





async function main() {

const { execSync } = require('child_process');
// Generate a new Ed25519 Keypair
const keypair = new Ed25519Keypair();


// Get faucet
const address = await keypair.getPublicKey().toSuiAddress()
	await requestSuiFromFaucetV0({
		host: getFaucetHost('testnet'),
		recipient: address,
	});
console.log(`The address is :`, address);
const client = new SuiClient({
	url: 'https://obcrpc.openblock.vip/',
});
const packagePath = `./my_first_package/delopy.json`


// generate the modules, and pad them into the following two param `modules` & `dependencies`
const modules = ["oRzrCwYAAAAJAQAMAgwEAxBOBF4GBWR5B90BhAII4QNgBsEEKwzsBK4EAA0BAgEUAgYCCAITBQACAAAVAAEAAAQCAwAAAwQDAAAPAwMAAA4FAwAACwUDAAAMAwMAAAkGBwAABwgDAAESDQMBAAIBDAcBAAIQDgcBAAMFCgMAAxEQAwAECgoDAAoLCQULCwkPCgIKAgoCCgIKAgoCCgIKAgEBAw8KAgoCAQoCBQoCCgIKAgoCCgIBDwEHCAAAAgoCCgIJCgIKAgoCCgIKAgoCCgIKAgoCAQYKAgECAgcKCQAKCQABBgkAAQcKCQAKCgIKAgMDCgIKAgoCBwIGAgYCAwYKAgYKAgIJVHhDb250ZXh0BmFwcGVuZANiY3MOY29tcHV0ZV9kaWdlc3QQY29tcHV0ZV9yb290aGFzaBFkZWNvbXByZXNzX3B1YmtleQhlY2RzYV9rMRdlcmVjb3Zlcl90b19ldGhfYWRkcmVzcwRoYXNoBGluaXQJa2VjY2FrMjU2DmtlY2NhazI1Nl91MjU2EGtlY2NhazI1Nl92ZWN0b3IJbXlfbW9kdWxlCXBhY2tfdTI1NhJwYWRfc2lnbmVkX21lc3NhZ2UHcmV2ZXJzZRNzZWNwMjU2azFfZWNyZWNvdmVyCHRvX2J5dGVzCnR4X2NvbnRleHQGdmVjdG9yCXZlcmlmeV9WQwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgoCCAdkaWQ6ems6CgIdHBlFdGhlcmV1bSBTaWduZWQgTWVzc2FnZToKMzIAAQQAAxELAAsBCwIRAQsDCwQLBQsGEQIRAwwJCwcLCREICwghAgEAAAAJKAsAEQUMAw4DEQ4MBgsBEQYMBA4EEQ4MBwsCEQYMBQ4FEQ4MCEALAAAAAAAAAAAMCg0KCwY4AA0KCwc4AA4KEQ4MCUALAAAAAAAAAAAMCw0LCwk4AA0LCwg4AA4LEQ4CAgAAAAMXQAsAAAAAAAAAAAwFDQULADgADQUHADgADQULATgADQULAjgADQULAzgADQULBDgADgURDgIDAAAAAwpACwAAAAAAAAAADAENAQcBOAANAQsAOAALAQIEAAAAAwcOADgBDAENATgCCwECBQAAAAMJQAsAAAAAAAAAAAwBDQELABEEOAAOAREOAgYAAAADCEALAAAAAAAAAAAMAQ0BCwA4AA4BEQ4CBwAAAAcBAggAAAAPXw0ABkAAAAAAAAAAQwsMCQoJFDEbIQQNMQALCRUFJgoJFDEcIQQWMQELCRUFJgoJFDEjJAQkCgkUMQEXMQIZCwkVBSYLCQEOAA4BMQARDQwGDgYRDAwHQAsAAAAAAAAAAAwIBgEAAAAAAAAADAQKBAZBAAAAAAAAACMERAU3DgcKBEILDAoNCAsKFEQLCwQGAQAAAAAAAAAWDAQFMg4IEQ4MA0ALAAAAAAAAAAAMAgYMAAAAAAAAAAwFCgUGIAAAAAAAAAAjBF0FUA4DCgVCCwwLDQILCxRECwsFBgEAAAAAAAAAFgwFBUsLAgIA"];
const dependencies = ["0x0000000000000000000000000000000000000000000000000000000000000001","0x0000000000000000000000000000000000000000000000000000000000000002"];
// const { modules, dependencies } = JSON.parse(
// 	execSync(`sui move build --dump-bytecode-as-base64 --path ${packagePath}`, {
// 		encoding: 'utf-8',
// 	}),
// );
const tx = new TransactionBlock();
const [upgradeCap] = tx.publish({
	modules,
	dependencies,
});
tx.transferObjects([upgradeCap], tx.pure(address));

// console.log(await client.getBalance())
const result = await client.signAndExecuteTransactionBlock({
	signer: keypair,
	transactionBlock: tx,
});
console.log({ result });
   
}

main();


// get coins owned by an address
