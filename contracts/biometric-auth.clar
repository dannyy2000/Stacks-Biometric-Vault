;; Biometric Authentication Contract
;; Uses Clarity 4's secp256r1-verify for passkey/biometric authentication
;; Supports WebAuthn, Face ID, Touch ID, and hardware security keys

;; =============================================================================
;; CONSTANTS
;; =============================================================================

(define-constant contract-owner tx-sender)

;; Error codes
(define-constant err-owner-only (err u100))
(define-constant err-passkey-not-found (err u101))
(define-constant err-passkey-already-exists (err u102))
(define-constant err-invalid-signature (err u103))
(define-constant err-passkey-revoked (err u104))
(define-constant err-invalid-nonce (err u105))
(define-constant err-max-passkeys-reached (err u106))
(define-constant err-invalid-public-key (err u107))
(define-constant err-unauthorized (err u108))

;; Limits
(define-constant max-passkeys-per-wallet u10)

;; =============================================================================
;; DATA VARIABLES
;; =============================================================================

(define-data-var total-passkeys-registered uint u0)
(define-data-var total-verifications uint u0)

;; =============================================================================
;; DATA MAPS
;; =============================================================================

;; Passkey storage: maps (wallet-address, passkey-id) -> passkey-data
(define-map passkeys
    {wallet: principal, passkey-id: (buff 32)}
    {
        public-key: (buff 65),        ;; Uncompressed secp256r1 public key
        name: (string-ascii 50),       ;; User-friendly name (e.g., "iPhone 13")
        created-at: uint,              ;; Block height when registered
        last-used: uint,               ;; Last verification block height
        revoked: bool,                 ;; Revocation status
        verification-count: uint       ;; Number of successful verifications
    }
)

;; Wallet -> list of passkey IDs (for enumeration)
(define-map wallet-passkeys
    principal
    (list 10 (buff 32))
)

;; Nonce tracking for replay protection
(define-map nonces
    principal
    uint
)

;; =============================================================================
;; READ-ONLY FUNCTIONS
;; =============================================================================

(define-read-only (get-passkey (wallet principal) (passkey-id (buff 32)))
    (map-get? passkeys {wallet: wallet, passkey-id: passkey-id})
)

(define-read-only (get-wallet-passkeys (wallet principal))
    (default-to (list) (map-get? wallet-passkeys wallet))
)

(define-read-only (get-passkey-count (wallet principal))
    (len (get-wallet-passkeys wallet))
)

(define-read-only (get-nonce (wallet principal))
    (default-to u0 (map-get? nonces wallet))
)

(define-read-only (is-passkey-active (wallet principal) (passkey-id (buff 32)))
    (match (get-passkey wallet passkey-id)
        passkey-data (not (get revoked passkey-data))
        false
    )
)

(define-read-only (get-total-passkeys-registered)
    (var-get total-passkeys-registered)
)

(define-read-only (get-total-verifications)
    (var-get total-verifications)
)

;; Get all passkey details for a wallet
(define-read-only (get-all-passkey-details (wallet principal))
    (map get-passkey-details-helper (get-wallet-passkeys wallet))
)

(define-private (get-passkey-details-helper (passkey-id (buff 32)))
    {
        passkey-id: passkey-id,
        data: (map-get? passkeys {wallet: tx-sender, passkey-id: passkey-id})
    }
)

;; =============================================================================
;; PASSKEY REGISTRATION
;; =============================================================================

;; Register a new passkey for the caller's wallet
;; The passkey-id should be a hash of the public key or credential ID from WebAuthn
(define-public (register-passkey
    (passkey-id (buff 32))
    (public-key (buff 65))
    (name (string-ascii 50)))
    (let
        (
            (wallet tx-sender)
            (current-passkeys (get-wallet-passkeys wallet))
        )
        ;; Validations
        (asserts! (< (len current-passkeys) max-passkeys-per-wallet) err-max-passkeys-reached)
        (asserts! (is-none (get-passkey wallet passkey-id)) err-passkey-already-exists)
        (asserts! (is-valid-public-key public-key) err-invalid-public-key)

        ;; Store passkey data
        (map-set passkeys
            {wallet: wallet, passkey-id: passkey-id}
            {
                public-key: public-key,
                name: name,
                created-at: block-height,
                last-used: u0,
                revoked: false,
                verification-count: u0
            }
        )

        ;; Add to wallet's passkey list
        (map-set wallet-passkeys
            wallet
            (unwrap-panic (as-max-len? (append current-passkeys passkey-id) u10))
        )

        ;; Update stats
        (var-set total-passkeys-registered (+ (var-get total-passkeys-registered) u1))

        (print {
            event: "passkey-registered",
            wallet: wallet,
            passkey-id: passkey-id,
            name: name,
            block-height: block-height
        })

        (ok true)
    )
)

;; =============================================================================
;; SIGNATURE VERIFICATION - CLARITY 4 FEATURE
;; =============================================================================

;; CLARITY 4: Verify a signature using secp256r1-verify
;; This is the core function that enables biometric authentication on-chain
(define-public (verify-signature
    (message-hash (buff 32))
    (public-key (buff 65))
    (signature (buff 64)))
    (let
        (
            ;; CLARITY 4: Use secp256r1-verify to verify the signature
            (is-valid (secp256r1-verify message-hash public-key signature))
        )
        (if is-valid
            (begin
                (var-set total-verifications (+ (var-get total-verifications) u1))
                (ok true)
            )
            err-invalid-signature
        )
    )
)

;; Verify and authenticate: Check signature AND that passkey is registered
(define-public (authenticate
    (wallet principal)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64)))
    (let
        (
            (passkey-data (unwrap! (get-passkey wallet passkey-id) err-passkey-not-found))
            (public-key (get public-key passkey-data))
        )
        ;; Check passkey is not revoked
        (asserts! (not (get revoked passkey-data)) err-passkey-revoked)

        ;; CLARITY 4: Verify signature with secp256r1-verify
        (asserts! (secp256r1-verify message-hash public-key signature) err-invalid-signature)

        ;; Update last-used and verification count
        (map-set passkeys
            {wallet: wallet, passkey-id: passkey-id}
            (merge passkey-data {
                last-used: block-height,
                verification-count: (+ (get verification-count passkey-data) u1)
            })
        )

        ;; Update global stats
        (var-set total-verifications (+ (var-get total-verifications) u1))

        (print {
            event: "authentication-success",
            wallet: wallet,
            passkey-id: passkey-id,
            block-height: block-height
        })

        (ok true)
    )
)

;; Authenticate with nonce (for replay protection)
;; The message-hash should include the nonce to prevent replay attacks
(define-public (authenticate-with-nonce
    (wallet principal)
    (passkey-id (buff 32))
    (message-hash (buff 32))
    (signature (buff 64))
    (expected-nonce uint))
    (let
        (
            (current-nonce (get-nonce wallet))
        )
        ;; Verify nonce
        (asserts! (is-eq expected-nonce current-nonce) err-invalid-nonce)

        ;; Authenticate
        (try! (authenticate wallet passkey-id message-hash signature))

        ;; Increment nonce
        (map-set nonces wallet (+ current-nonce u1))

        (ok true)
    )
)

;; =============================================================================
;; PASSKEY MANAGEMENT
;; =============================================================================

;; Revoke a passkey (cannot be undone)
(define-public (revoke-passkey (passkey-id (buff 32)))
    (let
        (
            (wallet tx-sender)
            (passkey-data (unwrap! (get-passkey wallet passkey-id) err-passkey-not-found))
        )
        ;; Update passkey to revoked status
        (map-set passkeys
            {wallet: wallet, passkey-id: passkey-id}
            (merge passkey-data {revoked: true})
        )

        (print {
            event: "passkey-revoked",
            wallet: wallet,
            passkey-id: passkey-id,
            block-height: block-height
        })

        (ok true)
    )
)

;; Update passkey name
(define-public (update-passkey-name
    (passkey-id (buff 32))
    (new-name (string-ascii 50)))
    (let
        (
            (wallet tx-sender)
            (passkey-data (unwrap! (get-passkey wallet passkey-id) err-passkey-not-found))
        )
        ;; Update name
        (map-set passkeys
            {wallet: wallet, passkey-id: passkey-id}
            (merge passkey-data {name: new-name})
        )

        (print {
            event: "passkey-renamed",
            wallet: wallet,
            passkey-id: passkey-id,
            new-name: new-name
        })

        (ok true)
    )
)

;; =============================================================================
;; HELPER FUNCTIONS
;; =============================================================================

;; Validate that a public key is the correct length
;; secp256r1 public keys are 65 bytes uncompressed (0x04 + 32-byte X + 32-byte Y)
;; or 33 bytes compressed (0x02/0x03 + 32-byte X)
(define-private (is-valid-public-key (public-key (buff 65)))
    (let
        (
            (key-length (len public-key))
        )
        ;; Check for uncompressed format (65 bytes, starts with 0x04)
        (and
            (is-eq key-length u65)
            (is-eq (buff-to-uint-be (unwrap-panic (as-max-len? (unwrap-panic (slice? public-key u0 u1)) u1))) u4)
        )
    )
)

;; Convert first byte of buffer to uint for validation
(define-private (buff-to-uint-be (byte (buff 1)))
    (unwrap-panic (index-of 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff byte))
)

;; =============================================================================
;; ADMIN FUNCTIONS
;; =============================================================================

;; Emergency revoke (admin only) - for compromised passkeys
(define-public (admin-revoke-passkey
    (wallet principal)
    (passkey-id (buff 32)))
    (let
        (
            (passkey-data (unwrap! (get-passkey wallet passkey-id) err-passkey-not-found))
        )
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)

        (map-set passkeys
            {wallet: wallet, passkey-id: passkey-id}
            (merge passkey-data {revoked: true})
        )

        (print {
            event: "admin-passkey-revoked",
            wallet: wallet,
            passkey-id: passkey-id,
            admin: tx-sender
        })

        (ok true)
    )
)
