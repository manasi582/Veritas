# Ubuntu test checklist (v1.0.19)

For the person testing on Ubuntu 22.04 or 24.04 (x86_64). Tick each box and write down anything that differs from what is described. For every failure, copy the command and its full output.

Where a command uses `$(hostname)` it fills in this machine's name by itself; where this document says `<HOST>`, type the server's real name or IP address (never leave `<...>` in a file). Replace `1.0.19` if you test another release.

## 0. What you need

- [ ] An Ubuntu machine with `sudo`, at least 4 GB RAM and 5 GB free disk.
- [ ] Port 8000 reachable from the machine you browse from.
- [ ] A license file `veritas.vlic` for this machine (step 2). Without one the service refuses to start; that is expected.
- [ ] A browser on any computer.

## 1. Install the server

Download from https://github.com/shreyaaassss/Veritas/releases/tag/v1.0.19 :
`veritas_1.0.19_amd64.deb` and `veritas-agent_1.0.19_all.deb`.

```bash
sudo apt install ./veritas_1.0.19_amd64.deb
```

- [ ] Install finishes without errors.
- [ ] `veritas version` prints `Veritas 1.0.19`.
- [ ] `systemctl is-enabled veritas` prints `enabled`.
- [ ] `systemctl is-active veritas` does **not** say active (no license yet).

## 2. License

```bash
sudo veritas fingerprint
```

- [ ] It prints a line starting with `v2:`. **Send it to the Veritas contact** and wait for `veritas.vlic`.
- [ ] Running it twice prints the same value.

```bash
sudo veritas license /path/to/veritas.vlic
```

- [ ] The command ends with `Status: running` within about 90 seconds.
- [ ] `sudo veritas check` finishes without any FAIL lines (warnings are fine; note them).

## 3. First sign-in with the setup code

```bash
sudo veritas setup-code
```

- [ ] It prints a code like `XXXX-XXXX-XXXX`.
- [ ] `sudo journalctl -u veritas | grep "SETUP CODE"` also shows the banner.

In the browser open `https://<HOST>:8000` (accept the certificate warning).

- [ ] It sends you to the **setup** page.
- [ ] A **wrong** setup code is refused with a message about the code.
- [ ] A weak password (`password123`) is refused.
- [ ] Creating the administrator with the right code and a good password (10+ characters) works, and you land on the sign-in page.
- [ ] After that, `sudo veritas setup-code` says there is no code, and `/setup` redirects to sign-in.
- [ ] Sign in works.

## 4. First-run dashboard

- [ ] A welcome screen asks you to configure an organization.
- [ ] Click **Configure Organisation**: the form is **visible** (not hidden behind the welcome screen).
- [ ] Cancel returns to the welcome screen.
- [ ] Create an organization: ID `testco`, one field (`aadhaar`, category `aadhaar`, purpose `onboarding_kyc`, scope `onboarding_kyc`, retention `180`, system `kyc-service`) with **Data since** set to a date 30 days ago, and one identifier (name `aadhaar`, pattern `indian_aadhaar`, validator `aadhaar`).
- [ ] The toast says the organization was created and the welcome screen goes away.
- [ ] Bottom-left of the sidebar shows `Veritas v1.0.19`.
- [ ] **Policy** tab shows the field with the Data Since date. **Edit Policy** opens the form already filled in.
- [ ] No red or amber banner at the top of the dashboard (if there is one, write down the text).
- [ ] **Overview → System Health** shows green for Evidence Store, Agent Store, License, TLS, Disk, and **Backups & Chain** shows `pending` (first backup runs about 10 minutes after the start).

## 5. Install the agent

On the same machine (or a second one that can reach the server):

```bash
sudo apt install ./veritas-agent_1.0.19_all.deb
veritas-agent version
```

- [ ] Prints `Veritas Agent 1.0.19`.

In the dashboard open **Agents → Issue Registration Key**, leave *One agent*, press **Generate Key**, copy the key.

Create a log file the agent may read and give the agent its configuration:

```bash
sudo mkdir -p /var/log/testapp
sudo touch /var/log/testapp/app.log
sudo chown root:adm /var/log/testapp/app.log && sudo chmod 640 /var/log/testapp/app.log

sudo tee /etc/veritas-agent/config.yaml >/dev/null <<'EOF'
veritas_address: https://localhost:8000     # use the server's name or IP if the agent is on another machine
registration_key: "PASTE-THE-KEY-HERE"
source_label: ubuntu-test
tls:
  verify: false        # the server's certificate is self-signed
sources:
  - type: file
    path: /var/log/testapp/app.log
    source_system: kyc-service
EOF
sudo chown veritas-agent:veritas-agent /etc/veritas-agent/config.yaml && sudo chmod 640 /etc/veritas-agent/config.yaml
sudo nano /etc/veritas-agent/config.yaml     # replace PASTE-THE-KEY-HERE with the real key, save
sudo systemctl start veritas-agent
```

Nothing in the file may be left as a placeholder: `<HOST>` or `<...>` in the address stops v1.0.19's agent from connecting (retrying forever); later versions stop with a clear message.

- [ ] `systemctl is-active veritas-agent` prints `active`.
- [ ] `sudo journalctl -u veritas-agent -n 20` shows `Registered as VERITAS-AGENT-...`.
- [ ] The key does **not** appear anywhere in that log.
- [ ] **Agents** tab shows the agent as ACTIVE with version `1.0.19`, no "Outdated" badge, a recent heartbeat, and the source `app.log` as *reading*.

## 6. Telemetry becomes a finding

```bash
echo "DEBUG customer verified with Aadhaar 2345 6789 0124" | sudo tee -a /var/log/testapp/app.log
echo "INFO order ORD-583927 status updated to packed"      | sudo tee -a /var/log/testapp/app.log
```

- [ ] Within about 30 seconds **Audit Ledger** shows one new `EXPOSURE_001` finding for `kyc-service` (and none for the clean line).
- [ ] Open **Details**, press **Acknowledge**, then **Mark as Resolved**: each step succeeds.
- [ ] **Verify Cryptographic Hash Chain** says the chain is intact.
- [ ] Restart the agent (`sudo systemctl restart veritas-agent`): the log says `Using existing identity`, and the **Agents** tab still shows **one** agent.
- [ ] Stop the server (`sudo systemctl stop veritas`), append two more lines containing phone numbers (for example `phone 9876543210`), wait 10 seconds, start the server again. After it is up, the violations appear (nothing was lost).

## 7. Users and passwords

In the dashboard open **Users → Add User**: username `analyst1`, email `analyst1@example.com`, role **Viewer**, keep the generated password. Under *Organizations* add `testco`.

- [ ] The new user shows **Must set password**.
- [ ] In a private browser window sign in as `analyst1`: you are forced to **choose a new password** before anything else.
- [ ] A weak new password is refused; a good one works and the dashboard opens.
- [ ] The viewer sees **no** Users, Audit Log or Policy tabs and cannot change a finding's status.
- [ ] Back as administrator: **Reset password** for `analyst1` shows a temporary password once; the viewer's open session stops working; signing in with the temporary password again forces a change.
- [ ] Five wrong passwords for `analyst1` (from the sign-in page) lock that account: the sixth attempt, even with the right password, is refused with "Too many failed attempts". The Audit Log shows `ACCOUNT_LOCKED`. (It frees itself after 15 minutes.)
- [ ] `sudo veritas reset-password analyst1` prints a temporary password; signing in with it forces a password change. (Only available in releases after v1.0.19; skip on v1.0.19.)
- [ ] You cannot disable your own account, and the Users tab shows no Reset button on your own row.
- [ ] **Audit Log** shows entries for the user creation and the password reset (and none contains a password).

## 8. Operations

- [ ] After about 10 minutes: System Health → **Backups & Chain** turns `ok`, and a file exists: `sudo ls -l /var/lib/veritas/backups/` (permissions `-rw-------`).
- [ ] `sudo veritas install-cert` with no arguments prints usage. Create a test certificate and install it:

  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=$(hostname)" \
    -addext "subjectAltName=DNS:$(hostname),DNS:localhost" -keyout /tmp/t.key -out /tmp/t.crt
  sudo veritas install-cert /tmp/t.crt /tmp/t.key
  ```
  - [ ] It prints `Certificate installed` and the service restarts and comes back up.
  - [ ] `sudo ls /var/lib/veritas/certs/` shows the previous certificate kept with a timestamp.
  - [ ] A mismatched pair (use a different key) is refused with `does not belong`, and nothing changes.
  - [ ] The browser now shows the new certificate.
- [ ] Reboot the machine: both services start by themselves and the data is still there.

## 9. Removal

```bash
sudo apt remove -y veritas-agent && sudo apt purge -y veritas-agent
sudo apt remove -y veritas
```

- [ ] Services stop; `id veritas-agent` fails after the purge; `/etc/veritas-agent` and `/var/lib/veritas-agent` are gone.
- [ ] `/var/lib/veritas` is still there after `remove` (your data is kept).

## What to send back

1. A list of the boxes that failed, with the command and its output.
2. `veritas version`, `lsb_release -d`, `uname -m`.
3. `sudo journalctl -u veritas --no-pager | tail -100` and `sudo journalctl -u veritas-agent --no-pager | tail -100`.
4. Screenshots of anything that looked wrong in the dashboard.
