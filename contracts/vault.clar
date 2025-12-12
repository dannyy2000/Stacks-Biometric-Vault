;; Vault Contract
;; Biometric-secured asset management for STX and SIP-010 tokens
;; Integrates with biometric-auth.clar for passkey authentication

;; =============================================================================
;; CONSTANTS
;; =============================================================================

(define-constant contract-owner tx-sender)

;; Error codes (u200-u211 range to avoid conflict with biometric-auth u100-u108)
(define-constant err-not-authorized (err u200))
(define-constant err-insufficient-balance (err u201))
(define-constant err-invalid-amount (err u202))
(define-constant err-withdrawal-not-found (err u203))
(define-constant err-withdrawal-locked (err u204))
(define-constant err-withdrawal-executed (err u205))
(define-constant err-invalid-token (err u206))
(define-constant err-transfer-failed (err u207))
(define-constant err-batch-limit-exceeded (err u208))
(define-constant err-invalid-operation (err u209))
(define-constant err-time-lock-required (err u210))
(define-constant err-authentication-failed (err u211))
(define-constant err-withdrawal-cancelled (err u212))
(define-constant err-invalid-limits (err u213))

;; Limits and thresholds
(define-constant max-batch-operations u10)
(define-constant default-large-withdrawal-threshold u1000000) ;; 1 STX in micro-STX
(define-constant default-time-lock-blocks u144) ;; ~24 hours (1 block ≈ 10 min)

;; =============================================================================
;; DATA VARIABLES
;; =============================================================================

(define-data-var total-deposits uint u0)
(define-data-var total-withdrawals uint u0)
(define-data-var withdrawal-request-nonce uint u0)

;; =============================================================================
;; DATA MAPS
;; =============================================================================

;; STX balances per user
(define-map stx-balances principal uint)

;; SIP-010 token balances: {owner, token-contract} -> amount
(define-map token-balances
    {owner: principal, token: principal}
    uint
)

;; User-specific withdrawal limits (optional overrides of defaults)
(define-map user-limits
    principal
    {
        large-withdrawal-threshold: uint,
        time-lock-blocks: uint
    }
)

;; Pending time-locked withdrawals
(define-map pending-withdrawals
    {owner: principal, request-id: uint}
    {
        amount: uint,
        recipient: principal,
        token: (optional principal),  ;; none = STX, some = token address
        requested-at: uint,           ;; block-height when requested
        executed: bool,
        cancelled: bool
    }
)

;; Track pending withdrawal IDs per user (for enumeration)
(define-map user-pending-withdrawals
    principal
    (list 20 uint)
)

;; =============================================================================
;; SIP-010 TRAIT
;; =============================================================================

(define-trait sip-010-trait
    (
        (transfer (uint principal principal (optional (buff 34))) (response bool uint))
        (get-name () (response (string-ascii 32) uint))
        (get-symbol () (response (string-ascii 32) uint))
        (get-decimals () (response uint uint))
        (get-balance (principal) (response uint uint))
        (get-total-supply () (response uint uint))
        (get-token-uri () (response (optional (string-utf8 256)) uint))
    )
)

;; =============================================================================
;; READ-ONLY FUNCTIONS
;; =============================================================================

;; Get STX balance for an owner
(define-read-only (get-stx-balance (owner principal))
    (default-to u0 (map-get? stx-balances owner))
)

;; Get SIP-010 token balance for an owner
(define-read-only (get-token-balance (owner principal) (token principal))
    (default-to u0 (map-get? token-balances {owner: owner, token: token}))
)

;; Get user's withdrawal limits (custom or defaults)
(define-read-only (get-user-limits (owner principal))
    (default-to
        {
            large-withdrawal-threshold: default-large-withdrawal-threshold,
            time-lock-blocks: default-time-lock-blocks
        }
        (map-get? user-limits owner)
    )
)

;; Get pending withdrawal details
(define-read-only (get-pending-withdrawal (owner principal) (request-id uint))
    (map-get? pending-withdrawals {owner: owner, request-id: request-id})
)

;; Get all pending withdrawal IDs for a user
(define-read-only (get-user-pending-withdrawals (owner principal))
    (default-to (list) (map-get? user-pending-withdrawals owner))
)

;; Check if a pending withdrawal is ready to execute
(define-read-only (is-withdrawal-ready (owner principal) (request-id uint))
    (match (get-pending-withdrawal owner request-id)
        withdrawal
            (let
                (
                    (limits (get-user-limits owner))
                    (lock-blocks (get time-lock-blocks limits))
                    (time-elapsed (- block-height (get requested-at withdrawal)))
                )
                (and
                    (not (get executed withdrawal))
                    (not (get cancelled withdrawal))
                    (>= time-elapsed lock-blocks)
                )
            )
        false
    )
)

;; Get total STX held by contract
(define-read-only (get-contract-stx-balance)
    (stx-get-balance (as-contract tx-sender))
)

;; Get total deposit and withdrawal statistics
(define-read-only (get-total-stats)
    {
        total-deposits: (var-get total-deposits),
        total-withdrawals: (var-get total-withdrawals),
        pending-withdrawal-count: (var-get withdrawal-request-nonce)
    }
)

;; =============================================================================
;; PRIVATE HELPER FUNCTIONS
;; =============================================================================

;; Authenticate via biometric-auth contract
(define-private (verify-biometric-auth
    (wallet principal)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (match (contract-call? .biometric-auth authenticate
                wallet
                passkey-id
                message-hash
                signature)
        success (ok true)
        error err-authentication-failed
    )
)

;; Check if amount requires time lock based on user limits
(define-private (requires-time-lock (owner principal) (amount uint))
    (let
        (
            (limits (get-user-limits owner))
            (threshold (get large-withdrawal-threshold limits))
        )
        (>= amount threshold)
    )
)

;; Create a new pending withdrawal request
(define-private (create-pending-withdrawal
    (owner principal)
    (amount uint)
    (recipient principal)
    (token (optional principal)))
    (let
        (
            (request-id (var-get withdrawal-request-nonce))
            (current-pending (get-user-pending-withdrawals owner))
        )
        ;; Store pending withdrawal
        (map-set pending-withdrawals
            {owner: owner, request-id: request-id}
            {
                amount: amount,
                recipient: recipient,
                token: token,
                requested-at: block-height,
                executed: false,
                cancelled: false
            }
        )

        ;; Add to user's pending list
        (map-set user-pending-withdrawals
            owner
            (unwrap-panic (as-max-len? (append current-pending request-id) u20))
        )

        ;; Increment nonce
        (var-set withdrawal-request-nonce (+ request-id u1))

        ;; Return request ID
        (ok request-id)
    )
)

;; =============================================================================
;; DEPOSIT FUNCTIONS
;; =============================================================================

;; Deposit STX into vault
(define-public (deposit-stx (amount uint))
    (let
        (
            (sender tx-sender)
            (current-balance (get-stx-balance sender))
        )
        ;; Validate amount
        (asserts! (> amount u0) err-invalid-amount)

        ;; Transfer STX from sender to contract
        (try! (stx-transfer? amount sender (as-contract tx-sender)))

        ;; Update balance
        (map-set stx-balances sender (+ current-balance amount))

        ;; Update stats
        (var-set total-deposits (+ (var-get total-deposits) u1))

        ;; Emit event
        (print {
            event: "deposit-stx",
            owner: sender,
            amount: amount,
            new-balance: (+ current-balance amount),
            block-height: block-height
        })

        (ok true)
    )
)

;; Deposit SIP-010 tokens into vault
(define-public (deposit-token (token <sip-010-trait>) (amount uint))
    (let
        (
            (sender tx-sender)
            (token-address (contract-of token))
            (current-balance (get-token-balance sender token-address))
        )
        ;; Validate amount
        (asserts! (> amount u0) err-invalid-amount)

        ;; Transfer tokens from sender to contract
        (try! (contract-call? token transfer amount sender (as-contract tx-sender) none))

        ;; Update balance
        (map-set token-balances
            {owner: sender, token: token-address}
            (+ current-balance amount)
        )

        ;; Update stats
        (var-set total-deposits (+ (var-get total-deposits) u1))

        ;; Emit event
        (print {
            event: "deposit-token",
            owner: sender,
            token: token-address,
            amount: amount,
            new-balance: (+ current-balance amount),
            block-height: block-height
        })

        (ok true)
    )
)

;; =============================================================================
;; WITHDRAWAL FUNCTIONS
;; =============================================================================

;; Withdraw STX with biometric authentication
(define-public (withdraw-stx
    (amount uint)
    (recipient principal)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (let
        (
            (sender tx-sender)
            (current-balance (get-stx-balance sender))
        )
        ;; Authenticate
        (try! (verify-biometric-auth sender passkey-id message-hash signature))

        ;; Validate
        (asserts! (> amount u0) err-invalid-amount)
        (asserts! (>= current-balance amount) err-insufficient-balance)

        ;; Check if time lock required
        (if (requires-time-lock sender amount)
            ;; Create pending withdrawal
            (let
                (
                    (request-id (try! (create-pending-withdrawal sender amount recipient none)))
                )
                (print {
                    event: "withdrawal-requested",
                    owner: sender,
                    request-id: request-id,
                    amount: amount,
                    recipient: recipient,
                    token: none,
                    block-height: block-height
                })
                (ok request-id)
            )
            ;; Execute immediate withdrawal
            (begin
                ;; Update balance
                (map-set stx-balances sender (- current-balance amount))

                ;; Transfer STX as contract
                (try! (as-contract (stx-transfer? amount tx-sender recipient)))

                ;; Update stats
                (var-set total-withdrawals (+ (var-get total-withdrawals) u1))

                ;; Emit event
                (print {
                    event: "withdraw-stx",
                    owner: sender,
                    recipient: recipient,
                    amount: amount,
                    immediate: true,
                    block-height: block-height
                })

                (ok u0) ;; Return 0 for immediate execution
            )
        )
    )
)

;; Withdraw SIP-010 tokens with biometric authentication
(define-public (withdraw-token
    (token <sip-010-trait>)
    (amount uint)
    (recipient principal)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (let
        (
            (sender tx-sender)
            (token-address (contract-of token))
            (current-balance (get-token-balance sender token-address))
        )
        ;; Authenticate
        (try! (verify-biometric-auth sender passkey-id message-hash signature))

        ;; Validate
        (asserts! (> amount u0) err-invalid-amount)
        (asserts! (>= current-balance amount) err-insufficient-balance)

        ;; Check if time lock required
        (if (requires-time-lock sender amount)
            ;; Create pending withdrawal
            (let
                (
                    (request-id (try! (create-pending-withdrawal sender amount recipient (some token-address))))
                )
                (print {
                    event: "withdrawal-requested",
                    owner: sender,
                    request-id: request-id,
                    amount: amount,
                    recipient: recipient,
                    token: (some token-address),
                    block-height: block-height
                })
                (ok request-id)
            )
            ;; Execute immediate withdrawal
            (begin
                ;; Update balance
                (map-set token-balances
                    {owner: sender, token: token-address}
                    (- current-balance amount)
                )

                ;; Transfer tokens as contract
                (try! (as-contract (contract-call? token transfer amount tx-sender recipient none)))

                ;; Update stats
                (var-set total-withdrawals (+ (var-get total-withdrawals) u1))

                ;; Emit event
                (print {
                    event: "withdraw-token",
                    owner: sender,
                    token: token-address,
                    recipient: recipient,
                    amount: amount,
                    immediate: true,
                    block-height: block-height
                })

                (ok u0) ;; Return 0 for immediate execution
            )
        )
    )
)

;; =============================================================================
;; TIME LOCK MANAGEMENT
;; =============================================================================

;; Execute a pending withdrawal after time lock expires
(define-public (execute-pending-withdrawal (request-id uint))
    (let
        (
            (sender tx-sender)
            (withdrawal (unwrap! (get-pending-withdrawal sender request-id) err-withdrawal-not-found))
            (amount (get amount withdrawal))
            (recipient (get recipient withdrawal))
            (token-opt (get token withdrawal))
        )
        ;; Verify not already executed or cancelled
        (asserts! (not (get executed withdrawal)) err-withdrawal-executed)
        (asserts! (not (get cancelled withdrawal)) err-withdrawal-cancelled)

        ;; Verify time lock has elapsed
        (asserts! (is-withdrawal-ready sender request-id) err-withdrawal-locked)

        ;; Execute withdrawal based on token type
        (match token-opt
            token-address
            ;; Token withdrawal
            (let
                (
                    (current-balance (get-token-balance sender token-address))
                )
                (asserts! (>= current-balance amount) err-insufficient-balance)

                ;; Update balance
                (map-set token-balances
                    {owner: sender, token: token-address}
                    (- current-balance amount)
                )

                ;; Transfer tokens
                (try! (as-contract (stx-transfer? amount tx-sender recipient)))

                ;; Mark as executed
                (map-set pending-withdrawals
                    {owner: sender, request-id: request-id}
                    (merge withdrawal {executed: true})
                )

                ;; Update stats
                (var-set total-withdrawals (+ (var-get total-withdrawals) u1))

                ;; Emit event
                (print {
                    event: "withdrawal-executed",
                    owner: sender,
                    request-id: request-id,
                    amount: amount,
                    recipient: recipient,
                    token: (some token-address),
                    block-height: block-height
                })

                (ok true)
            )
            ;; STX withdrawal
            (let
                (
                    (current-balance (get-stx-balance sender))
                )
                (asserts! (>= current-balance amount) err-insufficient-balance)

                ;; Update balance
                (map-set stx-balances sender (- current-balance amount))

                ;; Transfer STX
                (try! (as-contract (stx-transfer? amount tx-sender recipient)))

                ;; Mark as executed
                (map-set pending-withdrawals
                    {owner: sender, request-id: request-id}
                    (merge withdrawal {executed: true})
                )

                ;; Update stats
                (var-set total-withdrawals (+ (var-get total-withdrawals) u1))

                ;; Emit event
                (print {
                    event: "withdrawal-executed",
                    owner: sender,
                    request-id: request-id,
                    amount: amount,
                    recipient: recipient,
                    token: none,
                    block-height: block-height
                })

                (ok true)
            )
        )
    )
)

;; Cancel a pending withdrawal with biometric authentication
(define-public (cancel-pending-withdrawal
    (request-id uint)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (let
        (
            (sender tx-sender)
            (withdrawal (unwrap! (get-pending-withdrawal sender request-id) err-withdrawal-not-found))
        )
        ;; Authenticate
        (try! (verify-biometric-auth sender passkey-id message-hash signature))

        ;; Verify not already executed
        (asserts! (not (get executed withdrawal)) err-withdrawal-executed)

        ;; Mark as cancelled
        (map-set pending-withdrawals
            {owner: sender, request-id: request-id}
            (merge withdrawal {cancelled: true})
        )

        ;; Emit event
        (print {
            event: "withdrawal-cancelled",
            owner: sender,
            request-id: request-id,
            block-height: block-height
        })

        (ok true)
    )
)

;; =============================================================================
;; CONFIGURATION FUNCTIONS
;; =============================================================================

;; Set user-specific withdrawal limits
(define-public (set-withdrawal-limits
    (threshold uint)
    (lock-blocks uint)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (let
        (
            (sender tx-sender)
        )
        ;; Authenticate
        (try! (verify-biometric-auth sender passkey-id message-hash signature))

        ;; Validate parameters (reasonable ranges)
        (asserts! (> threshold u0) err-invalid-limits)
        (asserts! (and (>= lock-blocks u1) (<= lock-blocks u1008)) err-invalid-limits) ;; 1 block to ~1 week

        ;; Update limits
        (map-set user-limits
            sender
            {
                large-withdrawal-threshold: threshold,
                time-lock-blocks: lock-blocks
            }
        )

        ;; Emit event
        (print {
            event: "limits-updated",
            owner: sender,
            threshold: threshold,
            lock-blocks: lock-blocks,
            block-height: block-height
        })

        (ok true)
    )
)

;; =============================================================================
;; BATCH OPERATIONS
;; =============================================================================

;; Execute multiple operations with a single biometric signature
(define-public (execute-batch
    (operations (list 10 {
        op-type: (string-ascii 20),
        amount: uint,
        token: (optional principal),
        recipient: (optional principal)
    }))
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (let
        (
            (sender tx-sender)
            (op-count (len operations))
        )
        ;; Authenticate ONCE for all operations
        (try! (verify-biometric-auth sender passkey-id message-hash signature))

        ;; Validate batch size
        (asserts! (<= op-count max-batch-operations) err-batch-limit-exceeded)
        (asserts! (> op-count u0) err-invalid-operation)

        ;; Execute all operations (fold will fail-fast on first error)
        (let
            (
                (results (fold execute-batch-operation operations {success: true, count: u0, error: none}))
            )
            ;; Check if all operations succeeded
            (asserts! (get success results) (unwrap-panic (get error results)))

            ;; Emit batch event
            (print {
                event: "batch-executed",
                owner: sender,
                operation-count: (get count results),
                block-height: block-height
            })

            (ok (get count results))
        )
    )
)

;; Private helper to execute a single operation within a batch
(define-private (execute-batch-operation
    (op {
        op-type: (string-ascii 20),
        amount: uint,
        token: (optional principal),
        recipient: (optional principal)
    })
    (state {success: bool, count: uint, error: (optional (response bool uint))}))
    ;; If previous operation failed, propagate failure
    (if (not (get success state))
        state
        ;; Execute operation based on type
        (let
            (
                (op-type (get op-type op))
                (amount (get amount op))
                (token-opt (get token op))
                (recipient-opt (get recipient op))
                (sender tx-sender)
            )
            ;; Match operation type and execute
            (if (is-eq op-type "deposit-stx")
                ;; Deposit STX
                (match (deposit-stx amount)
                    success {success: true, count: (+ (get count state) u1), error: none}
                    error {success: false, count: (get count state), error: (some (err error))}
                )
                (if (is-eq op-type "withdraw-stx-immediate")
                    ;; Withdraw STX (must be below time lock threshold)
                    (let
                        (
                            (recipient (unwrap-panic recipient-opt))
                            (current-balance (get-stx-balance sender))
                        )
                        ;; Validate
                        (if (and
                                (> amount u0)
                                (>= current-balance amount)
                                (not (requires-time-lock sender amount)))
                            ;; Execute immediate withdrawal
                            (match (begin
                                    (map-set stx-balances sender (- current-balance amount))
                                    (as-contract (stx-transfer? amount tx-sender recipient)))
                                success
                                    (begin
                                        (var-set total-withdrawals (+ (var-get total-withdrawals) u1))
                                        {success: true, count: (+ (get count state) u1), error: none}
                                    )
                                error {success: false, count: (get count state), error: (some (err error))}
                            )
                            {success: false, count: (get count state), error: (some err-invalid-operation)}
                        )
                    )
                    ;; Unknown operation type
                    {success: false, count: (get count state), error: (some err-invalid-operation)}
                )
            )
        )
    )
)
