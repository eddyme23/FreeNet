#!/bin/bash
set -o pipefail

#by GuruzGH
#Script Variables

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='299'

# Dropbear Ports
Dropbear_Port1='790'
Dropbear_Port2='550'

# Stunnel Ports
Stunnel_Port='443' # through SSLH

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8000'
# Python Socks Proxy
WsPorts=('80' '8080' '8880' '2052' '2082' '2086' '2095')  # WS ports to listen on
WsPort='80'  # default WS port
WsResponse='HTTP/1.1 101 Switching Protocols\r\n\r\n'

# SSLH Port
MainPort='666' # main port to tunnel default 443

# SSH SlowDNS
# Nameserver='apvt-dns.guruzghvpn.site' # add NS server cloudflare
read -p "Enter SlowDNS Nameserver (or press enter for default): " -e -i "ns-dl.guruzgh.ovh" Nameserver
Serverkey='819d82813183e4be3ca1ad74387e47c0c993b81c601b2d1473a3f47731c404ae'
Serverpub='7fbd1f8aa0abfe15a7903e837f78aba39cf61d36f183bd604daa2fe4ef3b7b59'

# UDP HYSTERIA | UDP PORT | OBFS | PASSWORDS
UDP_PORT=":36712"

# Prompt installer for Hysteria obfs and password
_default_obfs='sa4uhy'
_default_password='EzUdp90hy'

if [ -t 0 ]; then
  # Prompt for obfs (user can press Enter to accept default)
  read -e -p "Enter Hysteria obfuscation string (obfs) [${_default_obfs}]: " -i "${_default_obfs}" _input_obfs
  OBFS="${_input_obfs:-${_default_obfs}}"

  # Prompt for password (user can press Enter to accept default)
  read -e -p "Enter Hysteria password [${_default_password}]: " -i "${_default_password}" _input_pass
  PASSWORD="${_input_pass:-${_default_password}}"
else
  # Non-interactive: use any pre-set env values or defaults
  OBFS="${OBFS:-${_default_obfs}}"
  PASSWORD="${PASSWORD:-${_default_password}}"
fi

export OBFS PASSWORD

# WebServer Ports
Nginx_Port='85' 

# DNS Resolver cloudflare dns
Dns_1='1.1.1.1' 
Dns_2='1.0.0.1'

# Server local time
MyVPS_Time='Africa/Accra'

# Telegram IDs
My_Chat_ID='835541277'
My_Bot_Key='5993251866:AAFVsuGJmf8fPNB4XgpQTxZ6aoubfLCEXd8'

######################################
###FreeNet AutoScript Code Begins...###
######################################

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

# Colours
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# Requirement
apt-get update
apt-get upgrade -y

# Initializing Server
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release



# =========================================================
# Debian / Ubuntu compatibility detection
# =========================================================
if [ "${ID}" != "ubuntu" ] && [ "${ID}" != "debian" ]; then
  echo "This installer supports Debian and Ubuntu only. Detected: ${ID}"
  exit 1
fi

# Detect service names / paths safely
SSH_SERVICE="ssh"
DROPBEAR_SERVICE="dropbear"
STUNNEL_SERVICE="stunnel4"
SQUID_SERVICE="squid"
SSLH_SERVICE="sslh"
NGINX_SERVICE="nginx"

# Prefer internal-sftp for cross-distro compatibility
SFTP_SUBSYSTEM="internal-sftp"

# Make sure required directories exist
mkdir -p /etc/dropbear /etc/stunnel /etc/nginx/conf.d /etc/deekayvpn /var/run/sslh

# Generate Dropbear keys only if missing
[ -f /etc/dropbear/dropbear_rsa_host_key ] || dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
[ -f /etc/dropbear/dropbear_dss_host_key ] || dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
[ -f /etc/dropbear/dropbear_ecdsa_host_key ] || dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key

# Make sure OpenSSH host keys exist
ssh-keygen -A >/dev/null 2>&1 || true

# Ensure resolver file exists
touch /etc/resolv.conf

if [ "${ID}" != "ubuntu" ] && [ "${ID}" != "debian" ]; then
  echo "This installer supports Debian and Ubuntu only. Detected: ${ID}"
  exit 1
fi

PACKAGE_LIST=(
  neofetch sslh dnsutils stunnel4 squid dropbear nano sudo wget unzip tar gzip
  iptables iptables-persistent netfilter-persistent bc cron dos2unix whois screen ruby
  python3 python3-pip apt-transport-https software-properties-common gnupg2
  ca-certificates curl net-tools nginx certbot jq python3-certbot-dns-cloudflare
  figlet git gcc make build-essential uwsgi uwsgi-plugin-python3 python3-dev perl expect
  libdbi-perl libnet-ssleay-perl libauthen-pam-perl libio-pty-perl apt-show-versions
  openssh-server rsyslog lsof procps
)

AVAILABLE_PACKAGES=()
for pkg in "${PACKAGE_LIST[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    AVAILABLE_PACKAGES+=("$pkg")
  fi
done

# Disable IPV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Add DNS server ipv4
rm -f /etc/resolv.conf
printf 'nameserver %s
nameserver %s
' "$Dns_1" "$Dns_2" > /etc/resolv.conf

# Set System Time
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

# NeoFetch (if necessary)
rm -f .profile
wget -O .profile "https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/Other/.profile"

# Installing some important machine essentials
apt-get install -y "${AVAILABLE_PACKAGES[@]}"

# Make sure base services exist on both Debian and Ubuntu
systemctl enable "$SSH_SERVICE" || true
systemctl enable rsyslog || true
systemctl restart rsyslog || true

# Installing a text colorizer and design
gem install lolcat

# purge if installed
apt -y --purge remove apache2 ufw firewalld

# Stop Nginx
systemctl stop nginx

# Download and install webmin
wget https://github.com/webmin/webmin/releases/download/2.111/webmin_2.111_all.deb
dpkg --install webmin_2.111_all.deb || apt-get install -f -y
sleep 1
rm -rf webmin_2.111_all.deb

# Use HTTP instead of HTTPS
sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf

# Restart Webmin service
systemctl restart webmin || true
systemctl status --no-pager webmin || true

# Banner
cat <<'deekay77' > /etc/zorro-luffy
<br><img alt="TmzxboghrK0LzxE8Qp/qP6Enw++EHeVt" 
style="display:none;">
<font color="#C12267">GURUZGH | FREENET | SERVER<br></font>
<br>
<font color="#b3b300"> x No DDOS<br></font>
<font color="#00cc00"> x No Torrent<br></font>
<font color="#ff1aff"> x No Spamming<br></font>
<font color="blue"> x No Phishing<br></font>
<font color="#A810FF"> x No Hacking<br></font>
<br>
<font color="red">• BROUGHT TO YOU BY <br></font><font color="#00cccc">https://t.me/GuruzGH !<br></font>
deekay77

# Removing some duplicated sshd server configs
rm -f /etc/ssh/sshd_config

# Creating a SSH server config using cat eof tricks
cat <<'MySSHConfig' > /etc/ssh/sshd_config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
MaxStartups 200:30:400
LoginGraceTime 30
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
Banner /etc/zorro-luffy
AcceptEnv LANG LC_*
Subsystem sftp SFTP_SUBSYSTEM
MySSHConfig

sleep 2
# Now we'll put our ssh ports inside of sshd_config
sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

sed -i "s|SFTP_SUBSYSTEM|$SFTP_SUBSYSTEM|g" /etc/ssh/sshd_config
# My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
sed -i 's/use_authtok //g' /etc/pam.d/common-password

# Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells

# Restarting openssh service
systemctl restart "$SSH_SERVICE"
systemctl status --no-pager "$SSH_SERVICE"

# Removing some duplicate config file
rm -rf /etc/default/dropbear*
 
# Creating dropbear config using cat eof tricks
cat <<'MyDropbear' > /etc/default/dropbear
# Deekay Script Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/zorro-luffy"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

# Now changing our desired dropbear ports
sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear

# Restarting dropbear service
systemctl restart "$DROPBEAR_SERVICE"
systemctl status --no-pager "$DROPBEAR_SERVICE"

cd /etc/default/
[ -f sslh ] && cp -f sslh sslh-old || true
cat << sslh > /etc/default/sslh
RUN=yes

DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen 127.0.0.1:$MainPort --ssh 127.0.0.1:$Dropbear_Port1 --http 127.0.0.1:$WsPort --pidfile /var/run/sslh/sslh.pid"

sslh

# Fix for sslh ubuntu
mkdir -p /var/run/sslh
touch /var/run/sslh/sslh.pid
chmod 777 /var/run/sslh/sslh.pid

# Restart service
systemctl daemon-reload
systemctl enable "$SSLH_SERVICE"
systemctl start "$SSLH_SERVICE"
systemctl restart "$SSLH_SERVICE"
systemctl status --no-pager "$SSLH_SERVICE"
cd

# Stunnel
StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

# Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/zorro-luffy"
PPP_RESTART=0
RLIMITS=""
MyStunnelD

# Removing all stunnel folder contents
rm -rf /etc/stunnel/*

# Creating stunnel server config
cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
syslog = no
debug = 0
output = /dev/null
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[sslh]
accept = Stunnel_Port
connect = 127.0.0.1:MainPort

MyStunnelC

cat <<'MyStunnelCert' > /etc/stunnel/stunnel.pem
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClmgCdm7RB2VWK
wfH8HO/T9bxEddWDsB3fJKpM/tiVMt4s/WMdGJtFdRlxzUb03u+HT6t00sLlZ78g
ngjxLpJGFpHAGdVf9vACBtrxv5qcrG5gd8k7MJ+FtMTcjeQm8kVRyIW7cOWxlpGY
6jringYZ6NcRTrh/OlxIHKdsLI9ddcekbYGyZVTm1wd22HVG+07PH/AeyY78O2+Z
tbjxGTFRSYt3jUaFeUmWNtxqWnR4MPmC+6iKvUKisV27P89g8v8CiZynAAWRJ0+A
qp+PWxwHi/iJ501WdLspeo8VkXIb3PivyIKC356m+yuuibD2uqwLZ2//afup84Qu
pRtgW/PbAgMBAAECggEAVo/efIQUQEtrlIF2jRNPJZuQ0rRJbHGV27tdrauU6MBT
NG8q7N2c5DymlT75NSyHRlKVzBYTPDjzxgf1oqR2X16Sxzh5uZTpthWBQtal6fmU
JKbYsDDlYc2xDZy5wsXnCC3qAaWs2xxadPUS3Lw/cjGsoeZlOFP4QtV/imLseaws
7r4KZE7SVO8dF8Xtcy304Bd7UsKClnbCrGsABUF/rqA8g34o7yrpo9XqcwbF5ihQ
TbnB0Ns8Bz30pjgGjJZTdTL3eskP9qMJWo/JM76kSaJWReoXTws4DlQHxO29z3eK
zKdxieXaBGMwFnv23JvXKJ5eAnxzqsL6a+SuNPPN4QKBgQDQhisSDdjUJWy0DLnJ
/HjtsnQyfl0efOqAlUEir8r5IdzDTtAEcW6GwPj1rIOm79ZeyysT1pGN6eulzS1i
6lz6/c5uHA9Z+7LT48ZaQjmKF06ItdfHI9ytoXaaQPMqW7NnyOFxCcTHBabmwQ+E
QZDFkM6vVXL37Sz4JyxuIwCNMQKBgQDLThgKi+L3ps7y1dWayj+Z0tutK2JGDww7
6Ze6lD5gmRAURd0crIF8IEQMpvKlxQwkhqR4vEsdkiFFJQAaD+qZ9XQOkWSGXvKP
A/yzk0Xu3qL29ZqX+3CYVjkDbtVOLQC9TBG60IFZW79K/Zp6PhHkO8w6l+CBR+yR
X4+8x1ReywKBgQCfSg52wSski94pABugh4OdGBgZRlw94PCF/v390En92/c3Hupa
qofi2mCT0w/Sox2f1hV3Fw6jWNDRHBYSnLMgbGeXx0mW1GX75OBtrG8l5L3yQu6t
SeDWpiPim8DlV52Jp3NHlU3DNrcTSOFgh3Fe6kpot56Wc5BJlCsliwlt0QKBgEol
u0LtbePgpI2QS41ewf96FcB8mCTxDAc11K6prm5QpLqgGFqC197LbcYnhUvMJ/eS
W53lHog0aYnsSrM2pttr194QTNds/Y4HaDyeM91AubLUNIPFonUMzVJhM86FP0XK
3pSBwwsyGPxirdpzlNbmsD+WcLz13GPQtH2nPTAtAoGAVloDEEjfj5gnZzEWTK5k
4oYWGlwySfcfbt8EnkY+B77UVeZxWnxpVC9PhsPNI1MTNET+CRqxNZzxWo3jVuz1
HtKSizJpaYQ6iarP4EvUdFxHBzjHX6WLahTgUq90YNaxQbXz51ARpid8sFbz1f37
jgjgxgxbitApzno0E2Pq/Kg=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIUOvs3vdjcBtCLww52CggSlAKafDkwDQYJKoZIhvcNAQEL
BQAwMjEQMA4GA1UEAwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNV
BAYTAlBIMB4XDTIxMDcwNzA1MzQwN1oXDTMxMDcwNTA1MzQwN1owMjEQMA4GA1UE
AwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNVBAYTAlBIMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApZoAnZu0QdlVisHx/Bzv0/W8RHXV
g7Ad3ySqTP7YlTLeLP1jHRibRXUZcc1G9N7vh0+rdNLC5We/IJ4I8S6SRhaRwBnV
X/bwAgba8b+anKxuYHfJOzCfhbTE3I3kJvJFUciFu3DlsZaRmOo64p4GGejXEU64
fzpcSBynbCyPXXXHpG2BsmVU5tcHdth1RvtOzx/wHsmO/DtvmbW48RkxUUmLd41G
hXlJljbcalp0eDD5gvuoir1CorFduz/PYPL/AomcpwAFkSdPgKqfj1scB4v4iedN
VnS7KXqPFZFyG9z4r8iCgt+epvsrromw9rqsC2dv/2n7qfOELqUbYFvz2wIDAQAB
o1MwUTAdBgNVHQ4EFgQUcKFL6tckon2uS3xGrpe1Zpa68VEwHwYDVR0jBBgwFoAU
cKFL6tckon2uS3xGrpe1Zpa68VEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAYQP0S67eoJWpAMavayS7NjK+6KMJtlmL8eot/3RKPLleOjEuCdLY
QvrP0Tl3M5gGt+I6WO7r+HKT2PuCN8BshIob8OGAEkuQ/YKEg9QyvmSm2XbPVBaG
RRFjvxFyeL4gtDlqb9hea62tep7+gCkeiccyp8+lmnS32rRtFa7PovmK5pUjkDOr
dpvCQlKoCRjZ/+OfUaanzYQSDrxdTSN8RtJhCZtd45QbxEXzHTEaICXLuXL6cmv7
tMuhgUoefS17gv1jqj/C9+6ogMVa+U7QqOvL5A7hbevHdF/k/TMn+qx4UdhrbL5Q
enL3UGT+BhRAPiA1I5CcG29RqjCzQoaCNg==
-----END CERTIFICATE-----
MyStunnelCert

# Setting stunnel ports
sed -i "s|MyDomain|$Cloudflare_Domain|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port|$Stunnel_Port|g" /etc/stunnel/stunnel.conf
sed -i "s|MainPort|$MainPort|g" /etc/stunnel/stunnel.conf

# Restarting stunnel service
systemctl restart "$STUNNEL_SERVICE"
systemctl enable "$STUNNEL_SERVICE"
systemctl status --no-pager "$STUNNEL_SERVICE"

# Setting Up Socks
loc=/etc/socksproxy
mkdir -p $loc

cat <<EOF > $loc/proxy.py
#!/usr/bin/env python3
import getopt
import select
import signal
import socket
import sys
import threading
import time

# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = $WsPort

PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:$Dropbear_Port1'
RESPONSE = b'$WsResponse'


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threads_lock = threading.Lock()
        self.log_lock = threading.Lock()
        self.soc = None

    def run(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(4096)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(True)
                except socket.timeout:
                    continue
                except OSError:
                    break

                conn = ConnectionHandler(c, self, addr)
                conn.daemon = True
                conn.start()
                self.add_conn(conn)
        finally:
            self.running = False
            try:
                if self.soc:
                    self.soc.close()
            except Exception:
                pass

    def print_log(self, log):
        with self.log_lock:
            print(log, flush=True)

    def add_conn(self, conn):
        with self.threads_lock:
            if self.running:
                self.threads.append(conn)

    def remove_conn(self, conn):
        with self.threads_lock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threads_lock:
            for c in list(self.threads):
                c.close()
        try:
            if self.soc:
                self.soc.close()
        except Exception:
            pass


class ConnectionHandler(threading.Thread):
    def __init__(self, soc_client, server, addr):
        super().__init__()
        self.client_closed = False
        self.target_closed = True
        self.client = soc_client
        self.client_buffer = b''
        self.server = server
        self.log = 'Connection: {}'.format(addr)
        self.target = None

    def close(self):
        try:
            if not self.client_closed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except Exception:
            pass
        finally:
            self.client_closed = True

        try:
            if not self.target_closed and self.target:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except Exception:
            pass
        finally:
            self.target_closed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            host_port = self.find_header(self.client_buffer, 'X-Real-Host')
            if host_port == '':
                host_port = DEFAULT_HOST

            split = self.find_header(self.client_buffer, 'X-Split')
            if split != '':
                self.client.recv(BUFLEN)

            if host_port != '':
                passwd = self.find_header(self.client_buffer, 'X-Pass')

                if len(PASS) != 0 and passwd == PASS:
                    self.method_connect(host_port)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.sendall(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif host_port.startswith('127.0.0.1') or host_port.startswith('localhost'):
                    self.method_connect(host_port)
                else:
                    self.client.sendall(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                self.server.print_log('- No X-Real-Host!')
                self.client.sendall(b'HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: {}'.format(str(e))
            self.server.print_log(self.log)
        finally:
            self.close()
            self.server.remove_conn(self)

    def find_header(self, head, header):
        try:
            text = head.decode('utf-8', errors='ignore')
        except Exception:
            return ''

        marker = header + ': '
        aux = text.find(marker)
        if aux == -1:
            return ''

        aux = text.find(':', aux)
        text = text[aux + 2:]
        aux = text.find('\r\n')
        if aux == -1:
            return ''

        return text[:aux]

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = LISTENING_PORT

        info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        soc_family, soc_type, proto, _, address = info[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.target_closed = False
        self.target.connect(address)

    def method_connect(self, path):
        self.log += ' - CONNECT {}'.format(path)
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = b''
        self.server.print_log(self.log)
        self.do_connect()

    def do_connect(self):
        socs = [self.client, self.target]
        count = 0
        error = False

        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)

            if err:
                error = True

            if recv:
                for in_sock in recv:
                    try:
                        data = in_sock.recv(BUFLEN)
                        if data:
                            if in_sock is self.target:
                                self.client.sendall(data)
                            else:
                                while data:
                                    sent = self.target.send(data)
                                    data = data[sent:]
                            count = 0
                        else:
                            error = True
                            break
                    except Exception:
                        error = True
                        break

            if count >= TIMEOUT:
                error = True

            if error:
                break


def print_usage():
    print('Usage: proxy.py -p <port>')
    print('       proxy.py -b <bindAddr> -p <port>')
    print('       proxy.py -b 0.0.0.0 -p $WsPort')


def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT

    try:
        opts, _ = getopt.getopt(argv, 'hb:p:', ['bind=', 'port='])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ('-b', '--bind'):
            LISTENING_ADDR = arg
        elif opt in ('-p', '--port'):
            LISTENING_PORT = int(arg)


def handle_signal(sig, frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print('\n:-------PythonProxy-------:\n')
    print('Listening addr: ' + LISTENING_ADDR)
    print('Listening port: ' + str(LISTENING_PORT) + '\n')
    print(':-------------------------:\n')

    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.daemon = True
    server.start()

    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('Stopping...')
            server.close()
            break


if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
EOF

chmod +x $loc/proxy.py

# Creating a template service so we can run WS on multiple ports
cat <<'service' > /etc/systemd/system/ws@.service
[Unit]
Description=Websocket Python3 (port %i)
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/socksproxy
Environment=PYTHONUNBUFFERED=1
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576
TasksMax=infinity
Restart=on-failure
RestartSec=2
ExecStartPre=/usr/bin/python3 -m py_compile /etc/socksproxy/proxy.py
ExecStart=/usr/bin/python3 -O /etc/socksproxy/proxy.py -b 0.0.0.0 -p %i
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ws@%i

[Install]
WantedBy=multi-user.target
service

# Start WS instances for every port in WsPorts[]
systemctl daemon-reload
for p in "${WsPorts[@]}"; do
  systemctl enable "ws@${p}"
  systemctl restart "ws@${p}"
done

# Show status for the primary WS ports
systemctl status --no-pager ws@80 ws@8080 ws@8880 || true

# NOTE: No iptables REDIRECT rules for WS ports. WS listens directly on each port in WsPorts[].

# Nginx configure
rm /home/vps/public_html -rf
rm /etc/nginx/sites-* -rf
rm /etc/nginx/nginx.conf -rf
sleep 1
mkdir -p /home/vps/public_html

# Creating nginx config for our webserver
cat <<'myNginxC' > /etc/nginx/nginx.conf

user www-data;

worker_processes auto;
pid /var/run/nginx.pid;

events {
	multi_accept on;
  worker_connections 8192;
}

http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types    text/plain application/x-javascript text/xml text/css;

	autoindex on;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;

	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;

	fastcgi_read_timeout 600;


  include /etc/nginx/conf.d/*.conf;
}
myNginxC

# Creating vps config for our OCS Panel
cat <<'myvpsC' > /etc/nginx/conf.d/vps.conf
server {
  listen       Nginx_Port;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/vps/public_html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }
}
myvpsC

# Setting up our WebServer Ports and IP Addresses
cd
sed -i "s|Nginx_Port|$Nginx_Port|g" /etc/nginx/conf.d/vps.conf

# Restarting nginx
systemctl restart "$NGINX_SERVICE"
systemctl status --no-pager "$NGINX_SERVICE"

# Removing Duplicate Squid config
rm -rf /etc/squid/squid.con*
 
# Creating Squid server config using cat eof tricks
cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl server dst IP-ADDRESS/32 localhost
acl checker src 188.93.95.137
acl ports_ port 14 22 53 21 8080 8081 8880 25 8000 3128 1193 1194 440 441 442 299 550 790 443 80
http_port Squid_Port1
http_port Squid_Port2
access_log none
cache_log /dev/null
logfile_rotate 0
max_filedescriptors 65535
http_access allow server
http_access allow checker
http_access deny all
http_access allow all
forwarded_for off
via off
request_header_access Host allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access All deny all
hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname IP-ADDRESS
mySquid

# Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf
 
# Setting squid ports
sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf
sed -i "s|Squid_Port2|$Squid_Port2|g" /etc/squid/squid.conf

# Starting Proxy server
echo -e "Restarting Squid Proxy server..."
systemctl restart "$SQUID_SERVICE"
systemctl status --no-pager "$SQUID_SERVICE"

# Make a folder
mkdir -p /etc/deekayvpn

# Cronjob script for auto restart services
cat <<'ServiceChecker' > /etc/deekayvpn/service_checker.sh
#!/bin/bash

MYID="MYCHATID"
KEY="MYBOTID"
URL="https://api.telegram.org/bot${KEY}/sendMessage"

send_telegram_message() {
    local TEXT="$1"
    curl -s --max-time 10 --retry 5 --retry-delay 2 --retry-max-time 10  -d "chat_id=${MYID}&text=${TEXT}&disable_web_page_preview=true&parse_mode=markdown" ${URL}
}

server_ip="IPADDRESS"
datenow=$(date +"%Y-%m-%d %T")
IPCOUNTRY=$(curl -s "https://freeipapi.com/api/json/${server_ip}" | jq -r '.countryName')

declare -A service_ports=(
    ["dropbear"]="DROPBEARPORT1,DROPBEARPORT2"
    ["stunnel4"]="STUNNELPORT"
    ["sslh"]="SSLHPORT"
    ["ws"]="WSPORTS"
    ["squid"]="SQUIDPORT1,SQUIDPORT2"
    ["nginx"]="NGINXPORT"
    ["sshd"]="SSHPORT1,SSHPORT2"
)

declare -A service_commands=(
    ["dropbear"]="sudo systemctl --force --force restart dropbear"
    ["stunnel4"]="sudo systemctl --force --force restart stunnel4"
    ["sslh"]="sudo systemctl --force --force restart sslh"
    ["ws"]="sudo systemctl --force --force restart WS_UNITS"
    ["squid"]="sudo systemctl --force --force restart squid"
    ["nginx"]="sudo systemctl --force --force restart nginx"
    ["sshd"]="sudo systemctl --force --force restart ssh"
)

for service in "${!service_ports[@]}"; do
    ports="${service_ports[$service]}"
    all_ports_ok=true

    # Special handling for WS (systemd template instances)
    if [ "$service" = "ws" ]; then
        for unit in WS_UNITS; do
            if ! systemctl is-active --quiet "$unit"; then
                all_ports_ok=false
                break
            fi
        done
        proc_ok=true
    else
        for port in ${ports//,/ }; do
            if ! netstat -ntlp | awk '{print $4}' | grep -q ":$port$"; then
                all_ports_ok=false
                break
            fi
        done
        proc_ok=false
        pgrep "$service" >/dev/null 2>&1 && proc_ok=true
    fi

    if [ "$proc_ok" = false ] || [ "$all_ports_ok" = false ]; then
        echo "$service is not functioning correctly (missing ports or process). Restarting..."
        eval "${service_commands[$service]}" >/dev/null 2>&1
        TEXT="Service *$service* was offline or missing port(s) *$ports* on server *${IPCOUNTRY}* ($server_ip). It has been restarted successfully at *${datenow}*."
        send_telegram_message "$TEXT"
    else
        echo "$service is running and all required ports are bound: $ports."
    fi
done
ServiceChecker

chmod -R 777 /etc/deekayvpn/service_checker.sh
sed -i "s|MYCHATID|$My_Chat_ID|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|MYCHANNELID|$My_Channel_ID|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|MYBOTID|$My_Bot_Key|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|IPADDRESS|$IPADDR|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|DROPBEARPORT1|$Dropbear_Port1|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s\|DROPBEARPORT2\|\$Dropbear_Port2\|g" "/etc/deekayvpn/service_checker\.sh"
sed -i "s|WSPORTS|80,8080,8880,2052,2082,2086,2095|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|WS_UNITS|ws@80 ws@8080 ws@8880 ws@2052 ws@2082 ws@2086 ws@2095|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|STUNNELPORT|$Stunnel_Port|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SSLHPORT|$MainPort|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SQUIDPORT1|$Squid_Port1|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SQUIDPORT2|$Squid_Port2|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|NGINXPORT|$Nginx_Port|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SSHPORT1|$SSH_Port1|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SSHPORT2|$SSH_Port2|g" "/etc/deekayvpn/service_checker.sh"

# Webmin Configuration
sed -i '$ i\deekay: acl adsl-client ajaxterm apache at backup-config bacula-backup bandwidth bind8 burner change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dovecot exim exports fail2ban fdisk fetchmail file filemin filter firewall firewalld fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec iscsi-client iscsi-server iscsi-target iscsi-tgtd jabber krb5 ldap-client ldap-server ldap-useradmin logrotate lpadmin lvm mailboxes mailcap man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd qmailadmin quota raid samba sarg sendmail servers shell shorewall shorewall6 smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webmincron webminlog wuftpd xinetd' /etc/webmin/webmin.acl
sed -i '$ i\deekay:0' /etc/webmin/miniserv.users
/usr/share/webmin/changepass.pl /etc/webmin deekay 20037

# Some Settings
sed -i "s|#SystemMaxUse=|SystemMaxUse=10M|g" /etc/systemd/journald.conf
sed -i "s|#SystemMaxFileSize=|SystemMaxFileSize=1M|g" /etc/systemd/journald.conf
systemctl restart systemd-journald


# High-concurrency tuning for Debian/Ubuntu
cat <<'SYSCTL' > /etc/sysctl.d/99-freenet-tuning.conf
fs.file-max = 1048576
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
SYSCTL
sysctl --system || true

mkdir -p /etc/security/limits.d
cat <<'LIMITS' > /etc/security/limits.d/99-freenet.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS

# Log Settings
rm -f /etc/logrotate.d/rsyslog
cat <<'logrotate' > /etc/logrotate.d/rsyslog
/var/log/syslog
{
        daily
        missingok
        notifempty
        create 640 syslog adm
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}

/var/log/kern.log
/var/log/auth.log
{
        rotate 1
        daily
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
logrotate
chown root:root /var/log
chmod 755 /var/log
chown root:root /var/log
chown syslog:adm /var/log/syslog
chmod 640 /var/log/syslog
logrotate -v -f /etc/logrotate.d/rsyslog

# CONFIGURE SLOWDNS
rm -rf /etc/slowdns
mkdir -m 777 /etc/slowdns
# ServerKEY
cat > /etc/slowdns/server.key << END
$Serverkey
END
# ServerPUB
cat > /etc/slowdns/server.pub << END
$Serverpub
END
wget -q -O /etc/slowdns/sldns-server "https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-server"
chmod +x /etc/slowdns/server.key
chmod +x /etc/slowdns/server.pub
chmod +x /etc/slowdns/sldns-server

# Iptables Rule for SlowDNS server
iptables -C INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# Install server-sldns.service
cat > /etc/systemd/system/server-sldns.service << END
[Unit]
Description=Server SlowDNS By FreeNet
Documentation=https://techguruzgh.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/sldns-server -udp :5300 -privkey-file /etc/slowdns/server.key $Nameserver 127.0.0.1:$SSH_Port2
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# Permission service slowdns
cd
chmod +x /etc/systemd/system/server-sldns.service
pkill sldns-server
systemctl daemon-reload
systemctl stop server-sldns
systemctl enable server-sldns
systemctl start server-sldns
systemctl restart server-sldns
systemctl status --no-pager server-sldns

# UDP hysteria
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/RepositoriesDexter/Hysteria/main/install_server.sh; chmod +x ~/install_server.sh; ./install_server.sh --version v1.3.5
rm -f /etc/hysteria/config.json

# Ensure /etc/hysteria exists
mkdir -p /etc/hysteria

# Derive numeric port from UDP_PORT (accepts formats like ":36712" or "0.0.0.0:36712")
HYST_PORT="${UDP_PORT##*:}"

# Create the hysteria config with proper variable expansion
cat > /etc/hysteria/config.json <<EOF
{
  "log_level": "fatal",
  "listen": "$UDP_PORT",
  "cert": "/etc/hysteria/hysteria.crt",
  "key": "/etc/hysteria/hysteria.key",
  "up_mbps": 8,
  "down_mbps": 15,
  "disable_udp": false,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": ["$PASSWORD"]
  }
}
EOF

# Creating Hysteria CERT
cat << EOF > /etc/hysteria/hysteria.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            40:26:da:91:18:2b:77:9c:85:6a:0c:bb:ca:90:53:fe
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=KobZ
        Validity
            Not Before: Jul 22 22:23:55 2020 GMT
            Not After : Jul 20 22:23:55 2030 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (1024 bit)
                Modulus:
                    00:ce:35:23:d8:5d:9f:b6:9b:cb:6a:89:e1:90:af:
                    42:df:5f:f8:bd:ad:a7:78:9a:ca:20:f0:3d:5b:d6:
                    c9:ef:4c:4a:99:96:c3:38:fd:59:b4:d7:65:ed:d4:
                    a7:fa:ab:03:e2:be:88:2f:ca:fc:90:dd:b0:b7:bc:
                    23:cb:83:ac:36:e2:01:57:69:64:b8:e1:9e:51:f0:
                    a6:9d:13:d9:92:6b:4d:04:a6:10:64:a3:3f:6b:ff:
                    fe:32:ac:91:63:c2:71:24:be:9e:76:4f:87:cc:3a:
                    03:a1:9e:48:3f:11:92:33:3b:19:16:9c:d0:5d:16:
                    ee:c1:42:67:99:47:66:67:67
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                6B:08:C0:64:10:71:A8:32:7F:0B:FE:1E:98:1F:BD:72:74:0F:C8:66
            X509v3 Authority Key Identifier: 
                keyid:64:49:32:6F:FE:66:62:F1:57:4D:BB:91:A8:5D:BD:26:3E:51:A4:D2
                DirName:/CN=KobZ
                serial:01:A4:01:02:93:12:D9:D6:01:A9:83:DC:03:73:DA:ED:C8:E3:C3:B7
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         a1:3e:ac:83:0b:e5:5d:ca:36:b7:d0:ab:d0:d9:73:66:d1:62:
         88:ce:3d:47:9e:08:0b:a0:5b:51:13:fc:7e:d7:6e:17:0e:bd:
         f5:d9:a9:d9:06:78:52:88:5a:e5:df:d3:32:22:4a:4b:08:6f:
         b1:22:80:4f:19:d1:5f:9d:b6:5a:17:f7:ad:70:a9:04:00:ff:
         fe:84:aa:e1:cb:0e:74:c0:1a:75:0b:3e:98:90:1d:22:ba:a4:
         7a:26:65:7d:d1:3b:5c:45:a1:77:22:ed:b6:6b:18:a3:c4:ee:
         3e:06:bb:0b:ec:12:ac:16:a5:50:b3:ed:46:43:87:72:fd:75:
         8c:38
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

chmod 755 /etc/hysteria/config.json
chmod 755 /etc/hysteria/hysteria.crt
chmod 755 /etc/hysteria/hysteria.key

# Add iptables NAT rule - use detected interface and the derived hysteria port
IFACE="$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1)"
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :$HYST_PORT 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :$HYST_PORT
systemctl enable hysteria-server.service
systemctl restart hysteria-server.service
systemctl status --no-pager hysteria-server.service

# Creating startup 1 script using cat eof tricks
cat <<'deekayz' > /etc/deekaystartup
#!/bin/sh

# Setting server local time
ln -fs /usr/share/zoneinfo/MyTimeZone /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing SlowDNS to Forward traffic
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# WS ports are handled by systemd instances ws@PORT (no iptables redirects)

# Disable IpV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# Add DNS server ipv4
echo "nameserver DNS1" > /etc/resolv.conf
echo "nameserver DNS2" >> /etc/resolv.conf

# For sslh
mkdir -p /var/run/sslh
touch /var/run/sslh/sslh.pid
chmod 777 /var/run/sslh/sslh.pid

# For udp
IFACE=$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1)
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :36712 2>/dev/null || iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 20000:50000 -j DNAT --to-destination :36712

deekayz

sed -i "s|MyTimeZone|$MyVPS_Time|g" /etc/deekaystartup
sed -i "s|DNS1|$Dns_1|g" /etc/deekaystartup
sed -i "s|DNS2|$Dns_2|g" /etc/deekaystartup
rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
cat <<'deekayx' > /etc/systemd/system/deekaystartup.service
[Unit]
Description=Custom startup script
ConditionPathExists=/etc/deekaystartup

[Service]
Type=oneshot
ExecStart=/etc/deekaystartup
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
deekayx

chmod +x /etc/deekaystartup
systemctl enable deekaystartup
systemctl start deekaystartup
systemctl status --no-pager deekaystartup
netfilter-persistent save || true
cd

# Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/jo6qznzwbsf1xhi/badvpn-udpgw64"
else
 wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/8gemt9c6k1fph26/badvpn-udpgw"
fi

# Change Permission to make it Executable
chmod +x /usr/bin/badvpn-udpgw
 
# Setting our startup script for badvpn
cat <<'deekayb' > /etc/systemd/system/badvpn.service
[Unit]
Description=badvpn tun2socks service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10

[Install]
WantedBy=multi-user.target
deekayb

systemctl enable badvpn
systemctl start badvpn
systemctl status --no-pager badvpn

# Some Final Cronjob
# Enable later after confirming all services work on this OS
# echo "* * * * * root /bin/bash /etc/deekayvpn/service_checker.sh >/dev/null 2>&1" > /etc/cron.d/service-checker
echo "*/2 * * * * root /usr/sbin/logrotate -v -f /etc/logrotate.d/rsyslog >/dev/null 2>&1" > /etc/cron.d/logrotate

# Install bundled premium menu
cd /usr/local/bin
cat > /usr/local/bin/menu <<'EOF_MENU'
#!/bin/bash

# GURUZGH Premium VPS Menu

RED='[1;31m'
GREEN='[1;32m'
YELLOW='[1;33m'
BLUE='[1;34m'
MAGENTA='[1;35m'
CYAN='[1;36m'
WHITE='[1;37m'
NC='[0m'

SERVER_IP=$(curl -4 -s --max-time 2 ipv4.icanhazip.com 2>/dev/null)
[ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="Unavailable"

TIMEZONE=$(cat /etc/timezone 2>/dev/null || readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
[ -z "$TIMEZONE" ] && TIMEZONE="System Default"

cpu_usage() {
  top -bn1 2>/dev/null | awk -F',' '/Cpu\(s\)/ {gsub("%us","",$1); gsub(" ","",$1); split($1,a,":"); print int(a[2]+0) "%"}'
}

ram_usage() {
  free -m 2>/dev/null | awk '/Mem:/ {printf "%sMB / %sMB", $3,$2}'
}

bar() {
  local pct="$1"
  local width=20
  local fill=$((pct * width / 100))
  local empty=$((width - fill))
  printf "["
  for ((i=0;i<fill;i++)); do printf "■"; done
  for ((i=0;i<empty;i++)); do printf "·"; done
  printf "]"
}

svc() {
  systemctl is-active --quiet "$1" 2>/dev/null && echo -e "${GREEN}ONLINE${NC}" || echo -e "${RED}OFFLINE${NC}"
}

count_port() {
  local port="$1"
  ss -Htan state established "( sport = :$port )" 2>/dev/null | wc -l
}

sum_ports() {
  local total=0
  for p in "$@"; do
    n=$(count_port "$p")
    total=$((total + n))
  done
  echo "$total"
}

ssh_users() {
  who 2>/dev/null | wc -l
}

create_user() {
  clear
  echo -e "${CYAN}Create SSH User${NC}"
  echo "--------------------------------"
  read -rp "Username: " user
  read -rsp "Password: " pass; echo
  read -rp "Valid for (days): " days

  if id "$user" &>/dev/null; then
    echo -e "${RED}User already exists.${NC}"
  else
    useradd -e "$(date -d "+$days days" +%Y-%m-%d)" -s /bin/false -M "$user" && \
    echo "$user:$pass" | chpasswd
    echo -e "${GREEN}User created successfully.${NC}"
  fi
  read -rp "Press ENTER to return..."
}

delete_user() {
  clear
  echo -e "${CYAN}Delete SSH User${NC}"
  echo "--------------------------------"
  read -rp "Username to delete: " user
  if id "$user" &>/dev/null; then
    userdel -r "$user" 2>/dev/null || userdel "$user"
    echo -e "${GREEN}User deleted.${NC}"
  else
    echo -e "${RED}User not found.${NC}"
  fi
  read -rp "Press ENTER to return..."
}

extend_user() {
  clear
  echo -e "${CYAN}Extend User Expiry${NC}"
  echo "--------------------------------"
  read -rp "Username: " user
  read -rp "Extend by how many days: " days
  if id "$user" &>/dev/null; then
    current=$(chage -l "$user" 2>/dev/null | awk -F": " '/Account expires/ {print $2}')
    if [ "$current" = "never" ] || [ -z "$current" ]; then
      new_exp=$(date -d "+$days days" +%Y-%m-%d)
    else
      new_exp=$(date -d "$current +$days days" +%Y-%m-%d)
    fi
    chage -E "$new_exp" "$user"
    echo -e "${GREEN}Expiry updated to $new_exp${NC}"
  else
    echo -e "${RED}User not found.${NC}"
  fi
  read -rp "Press ENTER to return..."
}

online_users() {
  clear
  echo -e "${CYAN}Online Users${NC}"
  echo "--------------------------------"
  who 2>/dev/null || echo "No active sessions found."
  echo
  echo "Active SSH/Dropbear connections:"
  ss -tnp 2>/dev/null | egrep ':(22|299|550|790)' || true
  read -rp "Press ENTER to return..."
}

list_users() {
  clear
  echo -e "${CYAN}System Users${NC}"
  echo "--------------------------------"
  awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd 2>/dev/null
  read -rp "Press ENTER to return..."
}

restart_all() {
  systemctl restart "$SSH_SERVICE" dropbear sslh stunnel4 squid nginx server-sldns hysteria-server badvpn 2>/dev/null || true
  for p in 80 8080 8880 2052 2082 2086 2095; do
    systemctl restart ws@"$p" 2>/dev/null || true
  done
  echo -e "${GREEN}All core services restarted.${NC}"
  read -rp "Press ENTER to return..."
}

restart_ssh_dropbear() {
  systemctl restart "$SSH_SERVICE" dropbear
  echo -e "${GREEN}SSH / Dropbear restarted.${NC}"
  read -rp "Press ENTER to return..."
}

restart_ws() {
  for p in 80 8080 8880 2052 2082 2086 2095; do
    systemctl restart ws@"$p" 2>/dev/null || true
  done
  echo -e "${GREEN}WebSocket services restarted.${NC}"
  read -rp "Press ENTER to return..."
}

restart_ssl() {
  systemctl restart "$STUNNEL_SERVICE" sslh
  echo -e "${GREEN}SSL / Stunnel / SSLH restarted.${NC}"
  read -rp "Press ENTER to return..."
}

restart_proxy() {
  systemctl restart "$SQUID_SERVICE" nginx
  echo -e "${GREEN}Squid / Proxy restarted.${NC}"
  read -rp "Press ENTER to return..."
}

restart_udp() {
  systemctl restart server-sldns hysteria-server badvpn 2>/dev/null || true
  echo -e "${GREEN}SlowDNS / Hysteria / BadVPN restarted.${NC}"
  read -rp "Press ENTER to return..."
}

show_dashboard() {
  clear
  cpu_num=$(cpu_usage | tr -d '%')
  [ -z "$cpu_num" ] && cpu_num=0

  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║                    GURUZGH ADMIN DASHBOARD                  ║${NC}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  printf " %-18s : %s
" "Server IP" "$SERVER_IP"
  printf " %-18s : %s
" "Timezone" "$TIMEZONE"
  printf " %-18s : %s
" "Time" "$(date)"
  printf " %-18s : %s %s
" "CPU Usage" "$(cpu_usage)" "$(bar "$cpu_num")"
  printf " %-18s : %s
" "RAM Usage" "$(ram_usage)"
  printf " %-18s : %s
" "SSH Users Online" "$(ssh_users)"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e " ${YELLOW}SERVICE STATUS${NC}"
  printf " %-18s : %b
" "SSH"        "$(svc ssh)"
  printf " %-18s : %b
" "Dropbear"   "$(svc dropbear)"
  printf " %-18s : %b
" "WebSocket"  "$(svc ws@80)"
  printf " %-18s : %b
" "Stunnel"    "$(svc stunnel4)"
  printf " %-18s : %b
" "SSLH"       "$(svc sslh)"
  printf " %-18s : %b
" "Squid"      "$(svc squid)"
  printf " %-18s : %b
" "SlowDNS"    "$(svc server-sldns)"
  printf " %-18s : %b
" "Hysteria"   "$(svc hysteria-server)"
  printf " %-18s : %b
" "BadVPN"     "$(svc badvpn)"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e " ${YELLOW}LIVE CONNECTION COUNTS${NC}"
  printf " %-18s : %s
" "SSH (22,299)" "$(sum_ports 22 299)"
  printf " %-18s : %s
" "Dropbear"     "$(sum_ports 790 550)"
  printf " %-18s : %s
" "WebSocket"    "$(sum_ports 80 8080 8880 2052 2082 2086 2095)"
  printf " %-18s : %s
" "SSL :443"     "$(count_port 443)"
  printf " %-18s : %s
" "Squid"        "$(sum_ports 3128 8000)"
  printf " %-18s : %s
" "SlowDNS"      "$(ss -Huan "( sport = :5300 )" 2>/dev/null | wc -l)"
  printf " %-18s : %s
" "Hysteria UDP" "$(ss -Huan "( sport = :36712 )" 2>/dev/null | wc -l)"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo
  read -rp "Press ENTER to return..."
}

show_ports() {
  clear
  echo -e "${CYAN}Open Ports${NC}"
  echo "--------------------------------"
  ss -lntup 2>/dev/null | egrep ':(22|299|443|550|666|790|85|80|8080|8880|2052|2082|2086|2095|3128|8000|5300|7300|36712)' || true
  read -rp "Press ENTER to return..."
}

show_nat() {
  clear
  echo -e "${CYAN}Firewall / NAT Rules${NC}"
  echo "--------------------------------"
  iptables -t nat -S 2>/dev/null || echo "No NAT rules found."
  echo
  iptables -S 2>/dev/null || true
  read -rp "Press ENTER to return..."
}

view_logs() {
  clear
  echo -e "${CYAN}Service Logs${NC}"
  echo "--------------------------------"
  echo "1) SSH"
  echo "2) Dropbear"
  echo "3) WebSocket"
  echo "4) Stunnel"
  echo "5) SSLH"
  echo "6) Squid"
  echo "7) Hysteria"
  echo "8) SlowDNS"
  read -rp "Choose service: " lopt
  case "$lopt" in
    1) journalctl -u ssh -n 50 --no-pager ;;
    2) journalctl -u dropbear -n 50 --no-pager ;;
    3) journalctl -u ws@80 -n 50 --no-pager ;;
    4) journalctl -u stunnel4 -n 50 --no-pager ;;
    5) journalctl -u sslh -n 50 --no-pager ;;
    6) journalctl -u squid -n 50 --no-pager ;;
    7) journalctl -u hysteria-server -n 50 --no-pager ;;
    8) journalctl -u server-sldns -n 50 --no-pager ;;
    *) echo "Invalid option." ;;
  esac
  read -rp "Press ENTER to return..."
}

view_hysteria() {
  clear
  echo -e "${CYAN}Hysteria Config${NC}"
  echo "--------------------------------"
  cat /etc/hysteria/config.json 2>/dev/null || echo "Config not found."
  read -rp "Press ENTER to return..."
}

protocol_guide() {
  clear
  cat <<GUIDE
GURUZGH PROTOCOL GUIDE
--------------------------------
SSH        : 22, 299
Dropbear   : 790, 550
Stunnel    : 443
SSLH       : 666
WebSocket  : 80, 8080, 8880, 2052, 2082, 2086, 2095
Squid      : 3128, 8000
SlowDNS    : 5300
Hysteria   : 36712/UDP
BadVPN     : 7300
Nginx      : 85

FLOW EXAMPLES
--------------------------------
SSL  : Client -> 443 -> Stunnel -> 666 -> SSLH -> Dropbear/WS
WS   : Client -> WS Port -> Python WS -> Dropbear
UDP  : Client -> UDP Range -> NAT -> 36712 -> Hysteria
GUIDE
  read -rp "Press ENTER to return..."
}

backup_snapshot() {
  out="/root/guruzgh_snapshot_$(date +%Y%m%d_%H%M%S).tar.gz"
  tar -czf "$out" /etc/ssh /etc/default/dropbear /etc/stunnel /etc/squid /etc/hysteria /etc/systemd/system/ws@.service /etc/deekayvpn 2>/dev/null
  echo -e "${GREEN}Snapshot saved:${NC} $out"
  read -rp "Press ENTER to return..."
}

draw_menu() {
  clear
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║                    GURUZGH ADMIN DASHBOARD                  ║${NC}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  printf " %-8s: %s
" "Server" "$SERVER_IP"
  printf " %-8s: %s
" "Time" "$(date '+%Y-%m-%d %H:%M:%S')"
  echo -e " ${WHITE}Status :${NC} SSH | DROPBEAR | WS | SSL | SQUID | DNS | UDP"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e " ${YELLOW}                     ACCOUNT MANAGEMENT${NC}"
  echo "  [1] Create SSH User"
  echo "  [2] Delete SSH User"
  echo "  [3] Extend User Expiry"
  echo "  [4] Check Online Users"
  echo "  [5] List All Users"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e " ${YELLOW}                     SERVICE CONTROL${NC}"
  echo "  [6] Restart All Services"
  echo "  [7] Restart SSH / Dropbear"
  echo "  [8] Restart WebSocket"
  echo "  [9] Restart SSL / Stunnel / SSLH"
  echo " [10] Restart Squid / Proxy"
  echo " [11] Restart SlowDNS / Hysteria / BadVPN"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e " ${YELLOW}                   MONITORING & TOOLS${NC}"
  echo " [12] Server Dashboard"
  echo " [13] Show Open Ports"
  echo " [14] Show Firewall / NAT Rules"
  echo " [15] View Service Logs"
  echo " [16] View Hysteria Config"
  echo " [17] Protocol Guide"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e " ${YELLOW}                     SYSTEM OPTIONS${NC}"
  echo " [18] Backup Config Snapshot"
  echo " [19] Reboot Server"
  echo "  [0] Exit"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo
}

while true; do
  draw_menu
  read -rp "Select option : " opt
  case "$opt" in
    1) create_user ;;
    2) delete_user ;;
    3) extend_user ;;
    4) online_users ;;
    5) list_users ;;
    6) restart_all ;;
    7) restart_ssh_dropbear ;;
    8) restart_ws ;;
    9) restart_ssl ;;
    10) restart_proxy ;;
    11) restart_udp ;;
    12) show_dashboard ;;
    13) show_ports ;;
    14) show_nat ;;
    15) view_logs ;;
    16) view_hysteria ;;
    17) protocol_guide ;;
    18) backup_snapshot ;;
    19) reboot ;;
    0) exit 0 ;;
    *) echo "Invalid option."; sleep 1 ;;
  esac
done

EOF_MENU
chmod +x /usr/local/bin/menu
cp /usr/local/bin/menu /usr/bin/menu
cp /usr/local/bin/menu /usr/bin/Menu
chmod +x /usr/bin/Menu
chmod +x /usr/bin/menu
cd

clear
cd
echo " "
echo " "
echo "PREMIUM SCRIPT SUCCESSFULLY INSTALLED!"
echo "SCRIPT BY GURUZGH"
echo "PLEASE WAIT..."
echo " "

# Finishing
chown -R www-data:www-data /home/vps/public_html

clear
echo ""
echo " INSTALLATION FINISH! "
echo ""
echo ""
echo "Server Information: " | tee -a log-install.txt | lolcat
echo "   • Timezone       : $MyVPS_Time "  | tee -a log-install.txt | lolcat
echo "   • IPtables       : [ON]"  | tee -a log-install.txt | lolcat
echo "   • Auto-Reboot    : [OFF] See menu to [ON] "  | tee -a log-install.txt | lolcat

echo " "| tee -a log-install.txt | lolcat
echo "Automated Features:"| tee -a log-install.txt | lolcat
echo "   • Auto restart server "| tee -a log-install.txt | lolcat
echo "   • Auto disconnect multilogin users [Openvpn]."| tee -a log-install.txt | lolcat
echo "   • Auto configure firewall every reboot[Protection for torrent and etc..]"| tee -a log-install.txt | lolcat
echo "   • Debian/Ubuntu compatibility improvements applied"| tee -a log-install.txt | lolcat
echo "   • High-concurrency tuning enabled for larger user counts"| tee -a log-install.txt | lolcat

echo " " | tee -a log-install.txt | lolcat
echo "Services & Port Information:" | tee -a log-install.txt | lolcat
echo "   • Dropbear             : [ON] : $Dropbear_Port1 | $Dropbear_Port2 " | tee -a log-install.txt | lolcat
echo "   • Squid Proxy          : [ON] : $Squid_Port1 | $Squid_Port2" | tee -a log-install.txt | lolcat
echo "   • SSL through Dropbear : [ON] : 443" | tee -a log-install.txt | lolcat
echo "   • SSH Websocket        : [ON] : 443 | 80 | 8080 | 8880 | 2052 | 2082 | 2086 | 2095" | tee -a log-install.txt | lolcat
echo "   • BadVPN               : [ON] : 7300 " | tee -a log-install.txt | lolcat
echo "   • Hysteria             : [ON] : 20000:50000" | tee -a log-install.txt | lolcat
echo "   • Nginx                : [ON] : $Nginx_Port" | tee -a log-install.txt | lolcat

echo "" | tee -a log-install.txt | lolcat
echo "Notes:" | tee -a log-install.txt | lolcat
echo "  ★ To display list of commands:  " [ menu ] or [ menu dk ] "" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo "  ★ Other concern and questions of these auto-scripts?" | tee -a log-install.txt | lolcat
echo "    Direct Messege : https://t.me/guruzgh" | tee -a log-install.txt | lolcat
echo ""

echo ""
echo "==================== PORTS SUMMARY (Post-Install) ====================" | tee -a log-install.txt
echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a log-install.txt
echo "" | tee -a log-install.txt

echo "[1/4] Systemd services (WS instances)" | tee -a log-install.txt
for p in "${WsPorts[@]}"; do
  systemctl is-active "ws@${p}" >/dev/null 2>&1 && \
    echo "  ws@${p}: active" | tee -a log-install.txt || \
    echo "  ws@${p}: NOT active (check: journalctl -u ws@${p} -n 50 --no-pager)" | tee -a log-install.txt
done
echo "" | tee -a log-install.txt

echo "[2/4] Listening sockets (TCP/UDP) - filtered" | tee -a log-install.txt
# Show listeners for the main ports used by this script
ss -lntup 2>/dev/null | egrep -n ':(22|80|85|299|443|550|666|790|3128|8000|8080|8880|2052|2082|2086|2095|5300|7300|36712)\b' | tee -a log-install.txt || true
echo "" | tee -a log-install.txt

echo "[3/4] NAT/Firewall rules (iptables -t nat) - relevant lines" | tee -a log-install.txt
iptables -t nat -S 2>/dev/null | egrep -n '(REDIRECT|DNAT|--dport 53|5300|36712|20000:50000|--dport 443|--dport 80|--dport 85|--dport 8080|--dport 8880|--dport 2052|--dport 2082|--dport 2086|--dport 2095)' | tee -a log-install.txt || true
echo "" | tee -a log-install.txt

echo "[4/4] Config quick-checks" | tee -a log-install.txt
echo "  Squid listen ports:" | tee -a log-install.txt
grep -nE '^\s*http_port\s+' /etc/squid/squid.conf 2>/dev/null | tee -a log-install.txt || true
echo "  Nginx listen ports:" | tee -a log-install.txt
grep -nE '^\s*listen\s+' /etc/nginx/conf.d/vps.conf 2>/dev/null | tee -a log-install.txt || true
echo "  Stunnel accept ports:" | tee -a log-install.txt
grep -nE '^\s*accept\s*=' /etc/stunnel/stunnel.conf 2>/dev/null | tee -a log-install.txt || true
echo "======================================================================" | tee -a log-install.txt
echo "" | tee -a log-install.txt


clear
echo ""
echo ""
figlet GuruzGH Script -c | lolcat
echo ""
echo "       Installation Complete! System need to reboot to apply all changes! "
history -c;
rm /root/full.sh
echo "           Server will secure this server and reboot after 10 seconds! "
sleep 10
reboot
