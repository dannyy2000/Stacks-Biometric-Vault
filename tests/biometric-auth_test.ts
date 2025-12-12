import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

// Test constants
const CONTRACT_NAME = 'biometric-auth';

// Mock secp256r1 public key (65 bytes uncompressed, starts with 0x04)
const VALID_PUBLIC_KEY = '0x04' + 'a'.repeat(128); // 0x04 + 64 hex chars (32 bytes X) + 64 hex chars (32 bytes Y)
const PASSKEY_ID = '0x' + '1'.repeat(64); // 32 bytes
const PASSKEY_ID_2 = '0x' + '2'.repeat(64);
const SIGNATURE = '0x' + 'b'.repeat(128); // 64 bytes
const MESSAGE_HASH = '0x' + 'c'.repeat(64); // 32 bytes

// Invalid keys for testing
const INVALID_KEY_SHORT = '0x04' + 'a'.repeat(126); // Too short
const INVALID_KEY_WRONG_PREFIX = '0x02' + 'a'.repeat(128); // Wrong prefix (compressed)

Clarinet.test({
    name: "Ensure that passkey registration works correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID),
                    types.buff(VALID_PUBLIC_KEY),
                    types.ascii('iPhone 13')
                ],
                wallet1.address
            )
        ]);

        // Should succeed
        assertEquals(block.receipts.length, 1);
        assertEquals(block.receipts[0].result, '(ok true)');

        // Verify passkey was stored
        let getPasskey = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-passkey',
            [types.principal(wallet1.address), types.buff(PASSKEY_ID)],
            wallet1.address
        );

        // Should return passkey data
        assert(getPasskey.result.includes('public-key'));
        assert(getPasskey.result.includes('iPhone 13'));
    },
});

Clarinet.test({
    name: "Ensure that invalid public keys are rejected",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Test with short key
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID),
                    types.buff(INVALID_KEY_SHORT),
                    types.ascii('Test Device')
                ],
                wallet1.address
            ),
            // Test with wrong prefix
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID_2),
                    types.buff(INVALID_KEY_WRONG_PREFIX),
                    types.ascii('Test Device 2')
                ],
                wallet1.address
            )
        ]);

        // Both should fail with err-invalid-public-key (u107)
        assertEquals(block.receipts[0].result, '(err u107)');
        assertEquals(block.receipts[1].result, '(err u107)');
    },
});

Clarinet.test({
    name: "Ensure that duplicate passkey IDs are rejected",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register first passkey
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID),
                    types.buff(VALID_PUBLIC_KEY),
                    types.ascii('Device 1')
                ],
                wallet1.address
            ),
            // Try to register same passkey ID again
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID),
                    types.buff(VALID_PUBLIC_KEY),
                    types.ascii('Device 2')
                ],
                wallet1.address
            )
        ]);

        // First should succeed
        assertEquals(block.receipts[0].result, '(ok true)');

        // Second should fail with err-passkey-already-exists (u102)
        assertEquals(block.receipts[1].result, '(err u102)');
    },
});

Clarinet.test({
    name: "Ensure that max passkeys per wallet limit is enforced",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Register 10 passkeys (max limit)
        let registerTxs = [];
        for (let i = 0; i < 10; i++) {
            const passkeyId = '0x' + i.toString(16).padStart(64, '0');
            registerTxs.push(
                Tx.contractCall(
                    CONTRACT_NAME,
                    'register-passkey',
                    [
                        types.buff(passkeyId),
                        types.buff(VALID_PUBLIC_KEY),
                        types.ascii(`Device ${i}`)
                    ],
                    wallet1.address
                )
            );
        }

        let block = chain.mineBlock(registerTxs);

        // All 10 should succeed
        for (let i = 0; i < 10; i++) {
            assertEquals(block.receipts[i].result, '(ok true)');
        }

        // Try to register 11th passkey
        let block2 = chain.mineBlock([
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff('0x' + 'f'.repeat(64)),
                    types.buff(VALID_PUBLIC_KEY),
                    types.ascii('Device 11')
                ],
                wallet1.address
            )
        ]);

        // Should fail with err-max-passkeys-reached (u106)
        assertEquals(block2.receipts[0].result, '(err u106)');
    },
});

Clarinet.test({
    name: "Ensure that passkey revocation works correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register passkey
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID),
                    types.buff(VALID_PUBLIC_KEY),
                    types.ascii('Test Device')
                ],
                wallet1.address
            ),
            // Revoke it
            Tx.contractCall(
                CONTRACT_NAME,
                'revoke-passkey',
                [types.buff(PASSKEY_ID)],
                wallet1.address
            )
        ]);

        assertEquals(block.receipts[0].result, '(ok true)');
        assertEquals(block.receipts[1].result, '(ok true)');

        // Check that passkey is marked as revoked
        let isActive = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'is-passkey-active',
            [types.principal(wallet1.address), types.buff(PASSKEY_ID)],
            wallet1.address
        );

        assertEquals(isActive.result, 'false');
    },
});

Clarinet.test({
    name: "Ensure that passkey name updates work correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register passkey
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [
                    types.buff(PASSKEY_ID),
                    types.buff(VALID_PUBLIC_KEY),
                    types.ascii('Old Name')
                ],
                wallet1.address
            ),
            // Update name
            Tx.contractCall(
                CONTRACT_NAME,
                'update-passkey-name',
                [
                    types.buff(PASSKEY_ID),
                    types.ascii('New Name')
                ],
                wallet1.address
            )
        ]);

        assertEquals(block.receipts[0].result, '(ok true)');
        assertEquals(block.receipts[1].result, '(ok true)');

        // Verify name was updated
        let getPasskey = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-passkey',
            [types.principal(wallet1.address), types.buff(PASSKEY_ID)],
            wallet1.address
        );

        assert(getPasskey.result.includes('New Name'));
    },
});

Clarinet.test({
    name: "Ensure that wallet passkey enumeration works",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Register 3 passkeys
        let block = chain.mineBlock([
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device 1')],
                wallet1.address
            ),
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [types.buff(PASSKEY_ID_2), types.buff(VALID_PUBLIC_KEY), types.ascii('Device 2')],
                wallet1.address
            ),
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [types.buff('0x' + '3'.repeat(64)), types.buff(VALID_PUBLIC_KEY), types.ascii('Device 3')],
                wallet1.address
            )
        ]);

        // Check passkey count
        let count = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-passkey-count',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assertEquals(count.result, 'u3');

        // Get all passkeys
        let passkeys = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-wallet-passkeys',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        // Should return list with 3 passkeys
        assert(passkeys.result.includes(PASSKEY_ID));
        assert(passkeys.result.includes(PASSKEY_ID_2));
    },
});

Clarinet.test({
    name: "Ensure that admin revoke works for contract owner",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Wallet registers passkey
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Test Device')],
                wallet1.address
            ),
            // Admin revokes it
            Tx.contractCall(
                CONTRACT_NAME,
                'admin-revoke-passkey',
                [types.principal(wallet1.address), types.buff(PASSKEY_ID)],
                deployer.address
            )
        ]);

        assertEquals(block.receipts[0].result, '(ok true)');
        assertEquals(block.receipts[1].result, '(ok true)');

        // Check that passkey is revoked
        let isActive = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'is-passkey-active',
            [types.principal(wallet1.address), types.buff(PASSKEY_ID)],
            wallet1.address
        );

        assertEquals(isActive.result, 'false');
    },
});

Clarinet.test({
    name: "Ensure that admin revoke fails for non-owner",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;
        const wallet2 = accounts.get('wallet_2')!;

        let block = chain.mineBlock([
            // Wallet1 registers passkey
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Test Device')],
                wallet1.address
            ),
            // Wallet2 tries to admin revoke (should fail)
            Tx.contractCall(
                CONTRACT_NAME,
                'admin-revoke-passkey',
                [types.principal(wallet1.address), types.buff(PASSKEY_ID)],
                wallet2.address
            )
        ]);

        assertEquals(block.receipts[0].result, '(ok true)');

        // Should fail with err-owner-only (u100)
        assertEquals(block.receipts[1].result, '(err u100)');
    },
});

Clarinet.test({
    name: "Ensure that nonce tracking works correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Initial nonce should be 0
        let nonce1 = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-nonce',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assertEquals(nonce1.result, 'u0');

        // Note: authenticate-with-nonce requires actual signature verification
        // which we can't easily mock in tests. This test verifies the nonce
        // getter works. Full integration testing would require real signatures.
    },
});

Clarinet.test({
    name: "Ensure that total stats tracking works",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Initial stats
        let stats1 = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-total-passkeys-registered',
            [],
            wallet1.address
        );

        assertEquals(stats1.result, 'u0');

        // Register a passkey
        let block = chain.mineBlock([
            Tx.contractCall(
                CONTRACT_NAME,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            )
        ]);

        // Check updated stats
        let stats2 = chain.callReadOnlyFn(
            CONTRACT_NAME,
            'get-total-passkeys-registered',
            [],
            wallet1.address
        );

        assertEquals(stats2.result, 'u1');
    },
});
