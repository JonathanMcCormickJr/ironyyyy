# Project Manager CLI

A security-conscious Rust CLI for basic Jira-style epic and story management. Each account keeps its data encrypted via AES-256-GCM with a key derived from the user password using Argon2id, and the CLI unlocks only after the password hash stored inside the encrypted payload has been validated.

## Getting started

1. Ensure you have Rust installed (stable channel).
2. Run the CLI:

   ```bash
   cargo run
   ```

   The first run creates a `/databases` directory plus a sample user file (username `demo`, password `demo-pass`). Future runs will list available users and prompt for the password.

3. After you log in, the command prompt accepts several operations (type `help` for a reminder):
   - `list epics` – shows every epic, its status, and story count.
   - `list stories` – prompts for an epic UUID and lists its stories.
   - `add epic` – creates a new epic with title, description, and status.
   - `add story` – appends a story to an epic with optional estimate metadata.
   - `update story status` – move a story through Backlog, In Progress, or Done.
   - `status summary` – prints how many epics sit in each status bucket.
   - `save` – immediately writes the encrypted data back to the user file.
   - `exit`/`quit` – saves and leaves the CLI.

## Database layout

Each user lives in `/databases/<uuid>.json`. The JSON schema is:

```json
{
  "metadata": {
    "uuid": "...",
    "username": "...",
    "created_at": 1700000000
  },
  "encrypted": {
    "nonce": "base64...",
    "payload": "base64..."
  }
}
```

- `metadata` is plaintext and used to present login choices.
- `encrypted.payload` decrypts with AES-GCM using a 256-bit key derived via Argon2id with the UUID bytes as the salt.
- The decrypted payload stores the Argon2 hash of the password plus the `ProjectData` (epics with nested stories). Within the payload, statuses are serialized in kebab-case (e.g., `in-progress`).

To add another user manually, copy the demo JSON file, update `metadata.username`, generate a new UUID for the filename, encrypt a payload with Argon2 and AES-GCM (the CLI currently creates such files when a user logs in and saves).

## Security notes

- Argon2id runs with a high memory/time combination (65 536 KiB, 8 passes) outside of tests to deter password cracking.
- AES-GCM uses a random 12-byte nonce for each update, stored in base64 alongside the ciphertext.
- The password hash lives inside the encrypted payload; the CLI does not reveal any user data until the hash is re-derived and verified.

## Validation steps

```bash
cargo fmt
cargo test
```

The test suite currently covers the Argon2/AES-GCM round trip defined next to `security.rs` and ensures the CLI code compiles cleanly.
