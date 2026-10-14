# Onboarding a customer (vendor runbook)

For the person at Veritas who sets up a new customer. The customer-side details are in [INSTALL.md](../INSTALL.md) (all platforms), [MACOS.md](MACOS.md) and [OPERATIONS.md](OPERATIONS.md). This page is the order of things and who does what.

## What you need

- Access to the License Portal (a separate repository, `veritas-license-portal`, deployed on Vercel) and its admin secret.
- The release to give the customer, from the [releases page](https://github.com/shreyaaassss/Veritas/releases/latest): `veritas_<version>_amd64.deb` (Ubuntu), `veritas_<version>_arm64.pkg` (Mac, Apple silicon) or `veritas_<version>_windows_amd64.exe`, and the matching agent package.
- The customer's machine for the server: Ubuntu 22.04+, a Mac with Apple silicon, or Windows 10+, with 4 GB RAM (2 GB minimum) and 2 GB free disk.

## 1. The customer installs the server

They install the package (Ubuntu: `sudo apt install ./veritas_<version>_amd64.deb`; Mac: `sudo installer -pkg ... -target /`, see MACOS.md). Veritas starts, finds no license and stops itself with a clear message. This is expected.

## 2. The customer sends the machine fingerprint

On the server they run `veritas fingerprint` and send you the **one line** it prints (it starts with `v2:` on Linux and macOS). The license works only on the machine that printed it.

Check what they send: it must be exactly that one line, with no spaces added and no characters missing. The portal refuses anything that does not look right, before signing.

## 3. You issue the license in the portal

1. Open the portal and sign in with the admin secret.
2. **+ Issue License**: organization ID (lowercase letters, digits and underscores, for example `acme_retail`), customer name, tier, expiry date, and paste the fingerprint.
3. **Generate License**, then **Download .vlic**. The portal keeps a record; you can download it again later.

Renewals and replacements (new expiry, or the customer's machine changed): use **Reissue** on the existing row. It replaces the old record and keeps one active license per organization. A license file already handed out cannot be recalled: it works until its expiry. **Delete record** only removes the entry from the portal's list.

## 4. You send the license, the customer installs it

Send the `.vlic` file. They run `sudo veritas license /path/to/file.vlic` (Windows: place it as described in INSTALL.md). The service starts and the dashboard is available.

## 5. The customer creates the administrator

`sudo veritas setup-code` prints a one-time code. They open `https://<server>:8000/setup`, enter the code and choose a username, email and password (10 characters or more). The page works only until the first administrator exists.

For a trusted certificate (no browser warning on every computer), use `sudo veritas install-cert <cert> <key>` with a certificate from their own CA.

## 6. The customer describes their data and connects agents

- In the dashboard they create the organization and declare the fields each system holds (purpose, consent scope, retention).
- On each machine to monitor they install the agent (Ubuntu `.deb`, Mac `.pkg`, Docker or Kubernetes), issue a registration key under **Agents**, put the server address and key in the agent's config and start it. Each agent should show as ACTIVE with a recent heartbeat.

## 7. Hand over

- Run `sudo veritas check` on the server together and clear anything it marks as failed.
- Show them the backup commands (`sudo veritas backup`, `restore`) and OPERATIONS.md. Backups run daily by themselves; they should copy them off the machine.
- Note the license expiry date in your own calendar; the customer's dashboard shows a warning 30 days before.

## Problems on the day

| Symptom | Likely cause and fix |
|---|---|
| "License is not valid for this machine" | The fingerprint came from a different machine, or the machine's hardware identifier changed. Get a fresh `veritas fingerprint` and **Reissue**. |
| Portal says the fingerprint is wrong | A typo or an extra character in the pasted line. Ask for the exact output again. |
| Portal says the organization already has a valid license | Use **Reissue** instead, unless a second license for the same organization is really intended. |
| Agent will not register | The key is single-use and expires after 30 minutes. Issue a new one. |
| Anything else | `sudo veritas logs` and the troubleshooting section of INSTALL.md. |
