# E2EE scope and key lifecycle

## Algorithm

Kawal-Trace event/audit envelopes use X25519 ephemeral key agreement, HKDF-SHA256 to derive a 256-bit content-encryption key, and AES-256-GCM for authenticated encryption. AES-GCM authenticates the ciphertext and associated routing metadata. This is a modern cryptographic construction, not a claim of an official “military-grade” certification.

The dashboard generates a receiver keypair. Its private key is stored in the OS Secure Storage via the native extension; the public key can be copied to enrolled agents. Agents encrypt audit/security event bodies to the public key. API validates envelope shape/limits and stores opaque ciphertext; API does not possess the dashboard private key. Do not downgrade to plaintext over an Internet connection if the public key is missing.

## Key steps

1. Login as local admin and generate a keypair once on the primary dashboard.
2. Export a private-key backup protected with a unique passphrase (minimum 14 characters; prefer a longer randomly generated phrase). Move JSON backup and passphrase through separate secure channels.
3. Copy the public key (not private key) to every enrolled Linux/Windows agent, then restart the agent.
4. On a second device, import the backup with the passphrase so the same receiver private key can decrypt historical envelopes.
5. Keep another offline encrypted backup. If the private key is lost and no backup exists, old encrypted telemetry becomes unreadable.
6. Rotate keys deliberately: deploy the new public key to all senders, record the cutover point, preserve the old private key for old event envelopes, and only then retire it.

## What is and is not encrypted

- **Encrypted end-to-end:** client audit payload and Linux/Windows security-event payload bodies.
- **Visible routing metadata:** API still sees minimal event ID, host/device ID, timestamp, event type, stream, sequence/checkpoint fields and source IP when required for routing/deduplication/action evidence.
- **HTTPS/TLS only, not E2EE yet:** Generic REST/JSON feeds and the current response-control API payloads. Response controls still have TLS, separate token, TOTP, typed confirmation, API-side validation and host-side validation. This current release must not be represented as full E2EE for every control message.

## Security considerations

- TLS remains mandatory with server certificate validation; E2EE does not replace TLS.
- X25519 encryption doesn't itself prove who sent a message; API token/device authentication and event chain/checkpoints complement it.
- A malicious endpoint can produce false telemetry. Compare multiple independent logs/checkpoints during an investigation.
- The system is a prototype and has not undergone independent cryptographic/security review.
