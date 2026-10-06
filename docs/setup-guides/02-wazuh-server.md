# 02: Wazuh server (manager, indexer, dashboard)

Runs on `wazuh-server` (10.10.10.10). Uses the official all-in-one installation assistant,
then tunes it for a 4 GB VM.

## 1. Install

Take the current 4.x version from the
[Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) and run its
installation-assistant command. It has this shape:

```bash
curl -sO https://packages.wazuh.com/<version>/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

At the end the assistant prints the `admin` password for the dashboard and leaves
`wazuh-install-files.tar` next to the script. **Store both in a password manager, then delete
the tarball from the VM.** This repository's `.gitignore` blocks the tarball and
`client.keys` so they can never be committed by accident.

## 2. Fit the indexer into 4 GB

The indexer's default heap is sized for dedicated servers. Apply
[`configs/sanitized/wazuh/indexer-jvm.options`](../../configs/sanitized/wazuh/indexer-jvm.options):

```bash
sudo sed -i 's/^-Xms.*/-Xms1g/; s/^-Xmx.*/-Xmx1g/' /etc/wazuh-indexer/jvm.options
sudo systemctl restart wazuh-indexer
free -h                                   # expect roughly 1 GB headroom left
```

## 3. Firewall

Only the lab network needs the agent ports, and only the host needs the dashboard:

```bash
sudo ufw allow from 10.10.10.0/24 to any port 1514,1515 proto tcp   # agent events + enrolment
sudo ufw allow from 10.10.10.1 to any port 443 proto tcp            # dashboard from the host
sudo ufw allow from 10.10.10.1 to any port 22 proto tcp             # SSH from the host
sudo ufw enable
sudo ufw status numbered
```

## 4. Verify

```bash
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard   # three times "active"
sudo /var/ossec/bin/wazuh-control status
```

Open `https://10.10.10.10` from the host browser and log in as `admin`. The certificate is
self-signed, so accept it for this lab only.

## 5. Deploy the lab's detection rules

Copy the repository to the server (for example `git clone`), then:

```bash
sudo bash scripts/deploy/deploy-rules.sh --dry-run
sudo bash scripts/deploy/deploy-rules.sh
```

The script backs up the existing rules, installs `detections/**/*.xml`, validates the whole
configuration with `wazuh-analysisd -t`, and rolls back automatically if validation fails.

Next: [03: Linux agent](03-linux-agent.md).
