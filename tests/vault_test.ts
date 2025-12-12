import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

// Test constants
const VAULT_CONTRACT = 'vault';
const AUTH_CONTRACT = 'biometric-auth';

// Mock data for biometric auth
const VALID_PUBLIC_KEY = '0x04' + 'a'.repeat(128);
const PASSKEY_ID = '0x' + '1'.repeat(64);
const SIGNATURE = '0x' + 'b'.repeat(128);
const MESSAGE_HASH = '0x' + 'c'.repeat(64);

// Test amounts
const SMALL_AMOUNT = 500000; // 0.5 STX (below threshold)
const LARGE_AMOUNT = 2000000; // 2 STX (above 1 STX threshold)
const DEPOSIT_AMOUNT = 5000000; // 5 STX

Clarinet.test({
    name: "Ensure that STX deposits work correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(DEPOSIT_AMOUNT)],
                wallet1.address
            )
        ]);

        // Should succeed
        assertEquals(block.receipts[0].result, '(ok true)');

        // Check balance was updated
        let balance = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assertEquals(balance.result, `u${DEPOSIT_AMOUNT}`);
    },
});

Clarinet.test({
    name: "Ensure that zero STX deposits are rejected",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(0)],
                wallet1.address
            )
        ]);

        // Should fail with err-invalid-amount (u202)
        assertEquals(block.receipts[0].result, '(err u202)');
    },
});

Clarinet.test({
    name: "Ensure that multiple deposits accumulate correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(1000000)],
                wallet1.address
            ),
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(2000000)],
                wallet1.address
            ),
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(500000)],
                wallet1.address
            )
        ]);

        // All should succeed
        assertEquals(block.receipts[0].result, '(ok true)');
        assertEquals(block.receipts[1].result, '(ok true)');
        assertEquals(block.receipts[2].result, '(ok true)');

        // Check total balance
        let balance = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assertEquals(balance.result, 'u3500000');
    },
});

Clarinet.test({
    name: "Ensure that balances are isolated between users",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;
        const wallet2 = accounts.get('wallet_2')!;

        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(1000000)],
                wallet1.address
            ),
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(2000000)],
                wallet2.address
            )
        ]);

        // Check wallet1 balance
        let balance1 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assertEquals(balance1.result, 'u1000000');

        // Check wallet2 balance
        let balance2 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet2.address)],
            wallet2.address
        );

        assertEquals(balance2.result, 'u2000000');
    },
});

Clarinet.test({
    name: "Ensure that withdrawal with insufficient balance fails",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;
        const wallet2 = accounts.get('wallet_2')!;

        let block = chain.mineBlock([
            // Register passkey first
            Tx.contractCall(
                AUTH_CONTRACT,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            ),
            // Deposit small amount
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(100000)],
                wallet1.address
            ),
            // Try to withdraw more than balance
            Tx.contractCall(
                VAULT_CONTRACT,
                'withdraw-stx',
                [
                    types.uint(200000),
                    types.principal(wallet2.address),
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            )
        ]);

        // Deposit should succeed
        assertEquals(block.receipts[1].result, '(ok true)');

        // Withdrawal should fail with err-insufficient-balance (u201)
        assertEquals(block.receipts[2].result, '(err u201)');
    },
});

Clarinet.test({
    name: "Ensure that user limits can be customized",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register passkey
            Tx.contractCall(
                AUTH_CONTRACT,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            ),
            // Set custom limits
            Tx.contractCall(
                VAULT_CONTRACT,
                'set-withdrawal-limits',
                [
                    types.uint(5000000), // 5 STX threshold
                    types.uint(288), // 48 hour delay
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            )
        ]);

        assertEquals(block.receipts[1].result, '(ok true)');

        // Check limits were set
        let limits = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-user-limits',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assert(limits.result.includes('u5000000'));
        assert(limits.result.includes('u288'));
    },
});

Clarinet.test({
    name: "Ensure that invalid limits are rejected",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register passkey
            Tx.contractCall(
                AUTH_CONTRACT,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            ),
            // Try to set zero threshold
            Tx.contractCall(
                VAULT_CONTRACT,
                'set-withdrawal-limits',
                [
                    types.uint(0),
                    types.uint(144),
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            ),
            // Try to set blocks > 1008 (>1 week)
            Tx.contractCall(
                VAULT_CONTRACT,
                'set-withdrawal-limits',
                [
                    types.uint(1000000),
                    types.uint(2000),
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            )
        ]);

        // Both should fail with err-invalid-limits (u213)
        assertEquals(block.receipts[1].result, '(err u213)');
        assertEquals(block.receipts[2].result, '(err u213)');
    },
});

Clarinet.test({
    name: "Ensure that default limits are used when not customized",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Get limits without setting custom ones
        let limits = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-user-limits',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        // Should return defaults: 1 STX (u1000000) and 144 blocks
        assert(limits.result.includes('u1000000'));
        assert(limits.result.includes('u144'));
    },
});

Clarinet.test({
    name: "Ensure that contract stats tracking works",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Initial stats
        let stats1 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-total-stats',
            [],
            wallet1.address
        );

        assert(stats1.result.includes('total-deposits: u0'));

        // Make deposits
        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(1000000)],
                wallet1.address
            ),
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(500000)],
                wallet1.address
            )
        ]);

        // Check updated stats
        let stats2 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-total-stats',
            [],
            wallet1.address
        );

        assert(stats2.result.includes('total-deposits: u2'));
    },
});

Clarinet.test({
    name: "Ensure that batch deposits work correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register passkey for auth
            Tx.contractCall(
                AUTH_CONTRACT,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            ),
            // Execute batch with 3 deposits
            Tx.contractCall(
                VAULT_CONTRACT,
                'execute-batch',
                [
                    types.list([
                        types.tuple({
                            'op-type': types.ascii('deposit-stx'),
                            'amount': types.uint(1000000),
                            'token': types.none(),
                            'recipient': types.none()
                        }),
                        types.tuple({
                            'op-type': types.ascii('deposit-stx'),
                            'amount': types.uint(500000),
                            'token': types.none(),
                            'recipient': types.none()
                        }),
                        types.tuple({
                            'op-type': types.ascii('deposit-stx'),
                            'amount': types.uint(250000),
                            'token': types.none(),
                            'recipient': types.none()
                        })
                    ]),
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            )
        ]);

        // Batch should succeed and return count of 3
        assertEquals(block.receipts[1].result, '(ok u3)');

        // Check total balance
        let balance = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        assertEquals(balance.result, 'u1750000');
    },
});

Clarinet.test({
    name: "Ensure that batch size limit is enforced",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Create 11 operations (exceeds max of 10)
        let operations = [];
        for (let i = 0; i < 11; i++) {
            operations.push(types.tuple({
                'op-type': types.ascii('deposit-stx'),
                'amount': types.uint(100000),
                'token': types.none(),
                'recipient': types.none()
            }));
        }

        let block = chain.mineBlock([
            // Register passkey
            Tx.contractCall(
                AUTH_CONTRACT,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            ),
            // Try batch with 11 operations
            Tx.contractCall(
                VAULT_CONTRACT,
                'execute-batch',
                [
                    types.list(operations),
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            )
        ]);

        // Should fail with err-batch-limit-exceeded (u208)
        assertEquals(block.receipts[1].result, '(err u208)');
    },
});

Clarinet.test({
    name: "Ensure that empty batch is rejected",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        let block = chain.mineBlock([
            // Register passkey
            Tx.contractCall(
                AUTH_CONTRACT,
                'register-passkey',
                [types.buff(PASSKEY_ID), types.buff(VALID_PUBLIC_KEY), types.ascii('Device')],
                wallet1.address
            ),
            // Try empty batch
            Tx.contractCall(
                VAULT_CONTRACT,
                'execute-batch',
                [
                    types.list([]),
                    types.buff(PASSKEY_ID),
                    types.buff(MESSAGE_HASH),
                    types.buff(SIGNATURE)
                ],
                wallet1.address
            )
        ]);

        // Should fail with err-invalid-operation (u209)
        assertEquals(block.receipts[1].result, '(err u209)');
    },
});

Clarinet.test({
    name: "Ensure that read-only functions don't modify state",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Deposit some STX
        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(1000000)],
                wallet1.address
            )
        ]);

        const balance1 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        // Call read-only function multiple times
        const balance2 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        const balance3 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-stx-balance',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        // All should return same result
        assertEquals(balance1.result, balance2.result);
        assertEquals(balance2.result, balance3.result);
        assertEquals(balance3.result, 'u1000000');
    },
});

Clarinet.test({
    name: "Ensure that pending withdrawals list is maintained correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;

        // Check initial pending list
        let pending1 = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-user-pending-withdrawals',
            [types.principal(wallet1.address)],
            wallet1.address
        );

        // Should be empty list
        assertEquals(pending1.result, '(list)');

        // Note: Creating actual pending withdrawals requires working biometric auth
        // which needs real signatures. This test verifies the getter works.
    },
});

Clarinet.test({
    name: "Ensure that contract STX balance tracking works",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;
        const wallet2 = accounts.get('wallet_2')!;

        let block = chain.mineBlock([
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(1000000)],
                wallet1.address
            ),
            Tx.contractCall(
                VAULT_CONTRACT,
                'deposit-stx',
                [types.uint(2000000)],
                wallet2.address
            )
        ]);

        // Check contract holds total STX
        let contractBalance = chain.callReadOnlyFn(
            VAULT_CONTRACT,
            'get-contract-stx-balance',
            [],
            wallet1.address
        );

        assertEquals(contractBalance.result, 'u3000000');
    },
});
