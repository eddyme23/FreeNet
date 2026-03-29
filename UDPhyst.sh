#!/bin/bash
set -o pipefail
clear

# 1. Initializing Server
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release 2>/dev/null

echo "============================================================"
echo "     Guruz Hysteria UDP Installer "
echo "============================================================"
sleep 2

# 2. Hysteria Variables
UDP_PORT=":36712"
_default_obfs='GuruzScript'
_default_password='GuruzScript'
read -e -p "Enter Hysteria obfs [${_default_obfs}]: " -i "${_default_obfs}" _input_obfs
OBFS="${_input_obfs:-${_default_obfs}}"
read -e -p "Enter Hysteria password [${_default_password}]: " -i "${_default_password}" _input_pass
PASSWORD="${_input_pass:-${_default_password}}"

# 3. Packages & Binary
apt-get update -y
apt-get install -y wget curl jq iptables iptables-persistent netfilter-persistent
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/RepositoriesDexter/Hysteria/main/install_server.sh
chmod +x ~/install_server.sh; ./install_server.sh --version v1.3.5

# 4. Configuration
mkdir -p /etc/hysteria
HYST_PORT="${UDP_PORT##*:}"
cat > /etc/hysteria/config.json <<EOF
{
  "log_level": "fatal",
  "listen": "$UDP_PORT",
  "cert": "/etc/hysteria/hysteria.crt",
  "key": "/etc/hysteria/hysteria.key",
  "up_mbps": 100,
  "down_mbps": 100,
  "disable_udp": false,
  "obfs": "$OBFS",
  "auth": { "mode": "passwords", "config": ["$PASSWORD"] }
}
EOF

# 5. Hardcoded Certs from original script
cat << EOF > /etc/hysteria/hysteria.crt
-----BEGIN CERTIFICATE-----
MIICVDCCAb2gAwIBAgIQQCbakRgrd5yFagy7ypBT/jANBgkqhkiG9w0BAQsFADAP
MQ0wCwYDVQQDDARLb2JaMB4XDTIwMDcyMjIyMjM1NVoXDTMwMDcyMDIyMjM1NVow
ETEPMA0GA1UEAwwGc2VydmVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO
NSPYXZ+2m8tqieGQr0LfX/i9rad4msog8D1b1snvTEqZlsM4/Vm012Xt1Kf6qwPi
vogvyvyQ3bC3vCPLg6w24gFXaWS44Z5R8KadE9mSa00EphBkoz9r//4yrJFjwnEk
vp52T4fMOgOhnkg/EZIzOxkWnNBdFu7BQmeZR2ZnZwIDAQABo4GuMIGrMAkGA1Ud
EwQCMAAwHQYDVR0OBBYEFGsIwGQQcagyfwv+HpgfvXJ0D8hmMEoGA1UdIwRDMEGA
FGRJMm/+ZmLxV027kahdvSY+UaTSoROkETAPMQ0wCwYDVQQDDARLb2JaghQBpAEC
kxLZ1gGpg9wDc9rtyOPDtzATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
BaAwEQYDVR0RBAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4GBAKE+rIML5V3K
NrfQq9DZc2bRYojOPUeeCAugW1ET/H7XbhcOvfXZqdkGeFKIWuXf0zIiSksIb7Ei
gE8Z0V+dtloX961wqQQA//6EquHLDnTAGnULPpiQHSK6pHomZX3RO1xFoXci7bZr
GKPE7j4GuwvsEqwWpVCz7UZDh3L9dYw4
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/hysteria/hysteria.key
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM41I9hdn7aby2qJ
4ZCvQt9f+L2tp3iayiDwPVvWye9MSpmWwzj9WbTXZe3Up/qrA+K+iC/K/JDdsLe8
I8uDrDbiAVdpZLjhnlHwpp0T2ZJrTQSmEGSjP2v//jKskWPCcSS+nnZPh8w6A6Ge
SD8RkjM7GRac0F0W7sFCZ5lHZmdnAgMBAAECgYAFNrC+UresDUpaWjwaxWOidDG8
0fwu/3Lm3Ewg21BlvX8RXQ94jGdNPDj2h27r1pEVlY2p767tFr3WF2qsRZsACJpI
qO1BaSbmhek6H++Fw3M4Y/YY+JD+t1eEBjJMa+DR5i8Vx3AE8XOdTXmkl/xK4jaB
EmLYA7POyK+xaDCeEQJBAPJadiYd3k9OeOaOMIX+StCs9OIMniRz+090AJZK4CMd
jiOJv0mbRy945D/TkcqoFhhScrke9qhgZbgFj11VbDkCQQDZ0aKBPiZdvDMjx8WE
y7jaltEDINTCxzmjEBZSeqNr14/2PG0X4GkBL6AAOLjEYgXiIvwfpoYE6IIWl3re
ebCfAkAHxPimrixzVGux0HsjwIw7dl//YzIqrwEugeSG7O2Ukpz87KySOoUks3Z1
yV2SJqNWskX1Q1Xa/gQkyyDWeCeZAkAbyDBI+ctc8082hhl8WZunTcs08fARM+X3
FWszc+76J1F2X7iubfIWs6Ndw95VNgd4E2xDATNg1uMYzJNgYvcTAkBoE8o3rKkp
em2n0WtGh6uXI9IC29tTQGr3jtxLckN/l9KsJ4gabbeKNoes74zdena1tRdfGqUG
JQbf7qSE3mg2
-----END PRIVATE KEY-----
EOF

# 6. Networking & Menu Setup
IFACE="$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1)"
iptables -I INPUT -p udp --dport "$HYST_PORT" -j ACCEPT
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :$HYST_PORT

cat > /etc/systemd/system/hysteria-nat.service <<EOF
[Unit]
Description=Restore Hysteria UDP NAT
Before=hysteria-server.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'IFACE=\$(ip -4 route ls|grep default|grep -Po "(?<=dev )(\\S+)"|head -1); iptables -t nat -C PREROUTING -i "\$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :$HYST_PORT 2>/dev/null || iptables -t nat -A PREROUTING -i "\$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :$HYST_PORT'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/menu <<'EOF_MENU'
#!/bin/bash
while true; do
    clear
    echo "GURUZ HYSTERIA MANAGER "
    systemctl is-active --quiet hysteria-server && echo "Status: ONLINE" || echo "Status: OFFLINE"
    echo -e "\n[1] View Config\n[2] Logs\n[3] Restart\n[4] Edit Creds\n[0] Exit"
    read -rp "Option: " opt
    case $opt in
        1) cat /etc/hysteria/config.json; read -p "Enter..." ;;
        2) journalctl -u hysteria-server -f ;;
        3) systemctl restart hysteria-server ;;
        4) read -p "New Obfs: " o; read -p "New Pass: " p; sed -i "s/\"obfs\": \".*\"/\"obfs\": \"$o\"/" /etc/hysteria/config.json; sed -i "s/\"config\": \[\".*\"\]/\"config\": [\"$p\"]/" /etc/hysteria/config.json; systemctl restart hysteria-server ;;
        0) exit 0 ;;
    esac
done
EOF_MENU

chmod +x /usr/local/bin/menu; ln -sf /usr/local/bin/menu /usr/bin/menu
systemctl daemon-reload; systemctl enable hysteria-nat hysteria-server; systemctl restart hysteria-nat hysteria-server
echo "Install Complete. Rebooting in 10s..."; sleep 10; reboot
