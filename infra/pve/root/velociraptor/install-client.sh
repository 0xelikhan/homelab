set -e
install -m 755 /tmp/velociraptor-bin /usr/local/bin/velociraptor
install -d -m 700 /etc/velociraptor
install -m 600 /tmp/client.config.yaml /etc/velociraptor/client.config.yaml
rm -f /tmp/velociraptor-bin /tmp/client.config.yaml
cat > /etc/systemd/system/velociraptor-client.service <<'U'
[Unit]
Description=Velociraptor client (DFIR agent, server 10.10.10.11)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/client.config.yaml client -v
Restart=always
RestartSec=30
LimitNOFILE=20000
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload
systemctl enable --now velociraptor-client >/dev/null 2>&1
sleep 4; systemctl is-active velociraptor-client
