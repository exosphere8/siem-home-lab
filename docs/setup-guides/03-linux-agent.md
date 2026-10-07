# 03: Linux agent (ubuntu-endpoint)

## 1. Install the agent from the Wazuh repository

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
# Same version as the manager (configs/wazuh-version): the agent must never be newer.
sudo WAZUH_MANAGER="10.10.10.10" WAZUH_AGENT_NAME="ubuntu-endpoint" apt-get install -y wazuh-agent=4.14.8-1
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo apt-mark hold wazuh-agent   # the agent must never be newer than the manager
```

## 2. Configure log sources and file-integrity monitoring

Merge [`configs/sanitized/wazuh/agent-linux-ossec.conf`](../../configs/sanitized/wazuh/agent-linux-ossec.conf)
into `/var/ossec/etc/ossec.conf`. Single files such as `/etc/passwd` are watched in *whodata*
mode, which needs auditd (real-time mode only works on directories):

```bash
sudo apt-get install -y auditd
sudo /var/ossec/bin/wazuh-control restart
```

Install the services the later projects monitor:

```bash
sudo apt-get install -y nginx                 # Project 6
```

## 3. Verify

On the **server**:

```bash
sudo /var/ossec/bin/agent_control -l        # ubuntu-endpoint listed as Active
```

On the **endpoint**, confirm the agent is reading the expected files:

```bash
sudo grep -E "Analyzing file|Started" /var/ossec/logs/ossec.log | tail
```

Next: [04: Windows agent](04-windows-agent.md).
