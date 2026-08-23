# Kerberos Authentication Protocol Demo

A simplified implementation of the Kerberos authentication protocol over TCP sockets, demonstrating ticket-based authentication with a Key Distribution Center (KDC), session keys, service tickets, and replay protection via authenticator timestamps.

## How it works

1. **TGT Request** — the client sends its username to the KDC (server).
2. **TGT + Session Key issuance** — the KDC derives the client's long-term key (Ka) from a password hash, generates a fresh Session Key (Sa), wraps Sa + client ID into a TGT encrypted with the KDC's own master key, and sends the whole payload back encrypted with Ka. The client independently derives the same Ka from the shared password to decrypt it.
3. **Service request** — the client builds a request containing the encrypted TGT, the requested file name, and an Authenticator (a timestamp encrypted with Sa), and sends it to the KDC.
4. **Freshness check** — the KDC decrypts the TGT with its master key to recover Sa, decrypts the Authenticator with Sa, and checks that the timestamp is within an acceptable window (60 seconds) to reject replayed requests.
5. **Service ticket issuance** — on success, the KDC generates a fresh Service Session Key (Kab), encrypts the requested file with it, and sends back the file name + Kab wrapped in a ticket encrypted with Sa.
6. **Data access** — the client decrypts the ticket, retrieves Kab, and uses it to decrypt the requested file.

## Security properties implemented

- Long-term key (Ka) is never sent over the network — both sides derive it independently from a shared password.
- Session keys (Sa, Kab) are ephemeral, generated fresh via `SecureRandom` for each exchange.
- AES-CBC encryption uses a random IV per operation (via `SecureRandom`), sent alongside the ciphertext — not derived deterministically from the key.
- Replay protection: the KDC validates the Authenticator's timestamp against its own clock using an actual time-duration comparison (`Duration`), rejecting requests outside a 60-second window.

## Known limitations

1. **Path traversal / arbitrary file access** — the requested file name is taken directly from client input (`requestedFileNameBytes`) and used as-is for both writing and reading files on the server's filesystem, with no validation or sanitization. A malicious client could submit a path like `../../../etc/passwd` or an absolute path to write to or read from locations outside the intended directory. This is independent of the Kerberos authentication logic itself — even a fully authenticated client can exploit it, since authentication proves identity but does not restrict which file name that identity is allowed to request. Not addressed in this demo due to time constraints; a production system would strip the path down to a bare filename (e.g. `Paths.get(fileName).getFileName().toString()`) and/or restrict access to a fixed, whitelisted directory.

2. **Password-derived key without salt or iteration** — the client's long-term key (Ka) is derived via a single SHA-256 pass over the password with no salt and no iteration count. This is weak against precomputed (rainbow table) and brute-force attacks. A production system would use a proper password-based KDF (PBKDF2, bcrypt, or Argon2).

3. **Hardcoded password** — the shared password (`"topsecret"`) is hardcoded in both client and server source code for demo purposes. In a real system this would come from a secure credential store, not source code.

4. **No mutual clock synchronization requirement documented** — the replay window relies on client and server clocks being reasonably in sync (standard Kerberos assumption), which isn't explicitly validated or enforced here.

## Running it

```bash
# Run the server
java KerberosServer

# Run the client (in a separate terminal)
java KerberosClient
```