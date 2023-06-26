#!/bin/bash
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# =========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
IZIN=$(wget -qO- ipinfo.io/ip);
clear
mkdir /var/lib/akbarstorevpn;
mkdir /var/lib/crot;
mkdir /etc/xray;
echo "IP=" >> /var/lib/crot/ipvps.conf
echo "IP=" >> /var/lib/akbarstorevpn/ipvps.conf
cd

# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================
#Getting
MYIP=$(wget -qO- ipinfo.io/ip);
# echo "Checking VPS"
# IZIN=$(curl https://raw.githubusercontent.com/lizsvr/project/main/ipvps.txt | grep $MYIP | awk '{print $3}')
# if [ $MYIP = $MYIP ]; then
# echo -e "${NC}${GREEN}Permission Accepted...${NC}"
# else
# echo -e "${NC}${RED}Permission Denied!${NC}";
# echo -e "${NC}${LIGHT}Please Contact Admin!!"
# echo -e "${NC}${LIGHT}Telegram : https://t.me/liz_mine"
# exit 0
# fi
error1="${RED} [ERROR] ${NC}"
success="${GREEN} [OK] ${NC}"
#Domain lama
source /var/lib/akbarstorevpn/ipvps.conf
if [[ "$IP" = "" ]]; then
domain=$(cat /etc/xray/domain)
else
domain=$IP
fi
clear
echo -e "========================="
read -rp "Input Domain/Host : " -e domain1
echo -e "========================="
echo -e "Domain di tambahkan: ${BLUE}${domain1} ${NC}Please Wait..."
echo -e "========================="
sleep 3

# Cek DNS terubung dengan VPS atau tidak
# cekdomain=$(curl -sm8 http://ipget.net/?ip="${domain1}")
# if [[ ${MYIP} == ${cekdomain} ]]; then
#     clear
#     echo -e "${success}Domain: ${BLUE}${domain1} ${NC}Terhubung dengan IP VPS"
#     sleep 3
# else
#     clear
#     echo -e "${error1}Domain: ${BLUE}${domain1} ${NC}Tidak Terhubung dengan IP VPS"
#     sleep 3
#     exit 0
#fi
# done
# Delete Files
rm -f /etc/xray/xray.crt
rm -f /etc/xray/xray.key
rm -f /root/domain
rm -f /etc/xray/domain
# Done
echo $domain1 >> /etc/xray/domain
echo $domain1 >> /root/domain
echo "IP=$domain1" >> /var/lib/akbarstorevpn/ipvps.conf
#Bersihkan terminal
clear
sleep 1

apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
timedatectl set-ntp true
systemctl enable chronyd && systemctl restart chronyd
systemctl enable chrony && systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
chronyc sourcestats -v
chronyc tracking -v
mkdir -p /etc/xray
sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
cd /root/
curl https://get.acme.sh | sh
bash acme.sh --install
cd .acme.sh
bash acme.sh --set-default-ca --server letsencrypt
bash acme.sh --register-account -m senowahyu62@gmail.com
bash acme.sh --issue -d $domain1 --standalone
bash acme.sh --installcert -d $domain1 --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key
sleep 3
clear

# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# =========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
# ==================================================
# Link Hosting Kalian
akbarvpn="raw.githubusercontent.com/lizsvr/cfnfree/main/ssh"

#
cd
# collor status
error1="${RED} [ERROR] ${NC}"
success="${GREEN} [OK] ${NC}"
# Cek Domain
source /var/lib/akbarstorevpn/ipvps.conf
if [[ "$IP" = "" ]]; then
    clear
    echo -e " ${error1}Gagal Install-tools.."
    sleep 2
    exit 0
else
    clear
    echo -e "${success}Installasi Tolls..."
    sleep2
fi
# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.

sslh-fix-reboot
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 100
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 100
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 100
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service
#
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
 
#alat
sudo apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev xl2tpd pptpd
#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

# install wget and curl
apt -y install wget curl
apt -y install net-tools

# Install Requirements Tools
apt install ruby -y
apt install python -y
apt install make -y
apt install cmake -y
apt install coreutils -y
apt install rsyslog -y
apt install net-tools -y
apt install zip -y
apt install unzip -y
apt install nano -y
apt install sed -y
apt install gnupg -y
apt install gnupg1 -y
apt install bc -y
apt install jq -y
apt install apt-transport-https -y
apt install build-essential -y
apt install dirmngr -y
apt install libxml-parser-perl -y
apt install neofetch -y
apt install git -y
apt install lsof -y
apt install libsqlite3-dev -y
apt install libz-dev -y
apt install gcc -y
apt install g++ -y
apt install libreadline-dev -y
apt install zlib1g-dev -y
apt install libssl-dev -y
apt install libssl1.0-dev -y
apt install dos2unix -y

#
# install
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git lsof
echo "clear" >> .profile
echo "neofetch" >> .profile

# install webserver
apt -y install nginx php php-fpm php-cli php-mysql libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
curl https://${akbarvpn}/nginx.conf > /etc/nginx/nginx.conf
curl https://${akbarvpn}/vps.conf > /etc/nginx/conf.d/vps.conf
sed -i 's/listen = \/var\/run\/php-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/fpm/pool.d/www.conf
useradd -m vps;
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html
cd /home/vps/public_html
wget -O /home/vps/public_html/index.html "https://${akbarvpn}/index.html1"
/etc/init.d/nginx restart
cd
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
cd

# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# =========================================
#
cd
# collor status
error1="${RED} [ERROR] ${NC}"
success="${GREEN} [OK] ${NC}"
# Cek Domain
# source /var/lib/akbarstorevpn/ipvps.conf
# if [[ "$IP" = "" ]]; then
#   clear
#   echo -e " ${error1}Gagal Install-Xray.."
#   sleep 2
#   exit 0
# else
#   clear
#   echo -e "${success}Installasi Xray..."
#   sleep 2
# fi

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
########################}


clear
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
NC='\e[0m'
echo "XRAY Core Vmess / Vless / Trojan / Shadowsocks"
echo "Trojan"
echo "Progress..."
sleep 3

domain=$(cat /root/domain)
sleep 1
mkdir -p /etc/xray 
echo -e "[ ${green}INFO${NC} ] Checking... "
apt install iptables iptables-persistent -y
sleep 1
echo -e "[ ${green}INFO$NC ] Setting ntpdate"
ntpdate pool.ntp.org 
timedatectl set-ntp true
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chronyd"
systemctl enable chronyd
systemctl restart chronyd
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chrony"
systemctl enable chrony
systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
sleep 1
echo -e "[ ${green}INFO$NC ] Setting chrony tracking"
chronyc sourcestats -v
chronyc tracking -v
echo -e "[ ${green}INFO$NC ] Setting dll"
apt clean all && apt update
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
apt install zip -y
apt install curl pwgen openssl netcat cron -y


# install xray
sleep 1
echo -e "[ ${green}INFO$NC ] Downloading & Installing xray core"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
# Make Folder XRay
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
touch /var/log/xray/error2.log
# / / Ambil Xray Core Version Terbaru
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
cp /usr/local/bin/xray /backup/xray.official.backup

# Download New Xray
cd /backup
wget -O xray.mod.backup "https://github.com/dharak36/Xray-core/releases/download/v1.0.0/xray.linux.64bit"


## crt xray
systemctl stop nginx
rm -rf /etc/nginx/conf.d/alone.conf

# nginx 
/etc/init.d/nginx stop

mkdir -p /home/vps/public_html

# set Cron
echo "0 5 * * * root xp && reboot" >> /etc/crontab


# Setting
uuid=$(cat /proc/sys/kernel/random/uuid)
# Set Xray Conf
cat > /usr/local/etc/xray/config.json << END
{
  "log" : {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": "2001",
      "protocol": "vless",
      "settings": {
        "decryption":"none",
        "clients": [
          {
            "id": "$uuid"
#vless
          }
        ]
      },
      "streamSettings":{
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2002",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0
#vmess
          }
        ]
      },
      "streamSettings":{
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2003",
      "protocol": "trojan",
      "settings": {
        "decryption":"none",
        "clients": [
          {
            "password": "$uuid"
#trojan
          }
        ],
        "udp": true
      },
      "streamSettings":{
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2004",
      "protocol": "socks",
      "settings": {
        "auth": "password",
        "accounts": [
            {
              "user": "admin",
              "pass": "admin"
#socks
            }
          ],
        "udp": true,
        "ip": "127.0.0.1"
      },
      "streamSettings":{
        "network": "ws",
        "wsSettings": {
          "path": "/socks-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2005",
      "protocol": "vless",
      "settings": {
        "decryption":"none",
        "clients": [
          {
            "id": "$uuid"
#vless-grpc
          }
        ]
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2006",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0
#vmess-grpc
          }
        ]
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2007",
      "protocol": "trojan",
      "settings": {
        "decryption":"none",
        "clients": [
          {
            "password": "$uuid"
#trojan-grpc
          }
        ],
        "udp": true
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "2008",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0
#vmessnontls
          }
        ]
      },
      "streamSettings":{
        "network": "ws",
        "wsSettings": {
          "path": "/"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END
rm -rf /etc/systemd/system/xray.service.d
cat <<EOF> /etc/systemd/system/xray.service
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
cat > /etc/systemd/system/runn.service <<EOF
[Unit]
Description=Mampus-Anjeng
After=network.target

[Service]
Type=simple
ExecStartPre=-/bin/mkdir -p /var/run/xray
ExecStart=/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

# Set Nginx Conf
cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes 1;
pid /var/run/nginx.pid;
events {
        multi_accept on;
        worker_connections 1024;
}
http {
        gzip on;
        gzip_vary on;
        gzip_comp_level 5;
        gzip_types text/plain application/x-javascript text/xml text/css;
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
        #CloudFlare IPv4
        set_real_ip_from 199.27.128.0/21;
        set_real_ip_from 173.245.48.0/20;
        set_real_ip_from 103.21.244.0/22;
        set_real_ip_from 103.22.200.0/22;
        set_real_ip_from 103.31.4.0/22;
        set_real_ip_from 141.101.64.0/18;
        set_real_ip_from 108.162.192.0/18;
        set_real_ip_from 190.93.240.0/20;
        set_real_ip_from 188.114.96.0/20;
        set_real_ip_from 197.234.240.0/22;
        set_real_ip_from 198.41.128.0/17;
        set_real_ip_from 162.158.0.0/15;
        set_real_ip_from 104.16.0.0/12;
        #Incapsula
        set_real_ip_from 199.83.128.0/21;
        set_real_ip_from 198.143.32.0/19;
        set_real_ip_from 149.126.72.0/21;
        set_real_ip_from 103.28.248.0/22;
        set_real_ip_from 45.64.64.0/22;
        set_real_ip_from 185.11.124.0/22;
        set_real_ip_from 192.230.64.0/18;
        real_ip_header CF-Connecting-IP;
        include /etc/nginx/conf.d/*.conf;
}
EOF

# Set Xray Nginx Conf
cat > /etc/nginx/conf.d/xray.conf << EOF
    server {
             listen 81;
             listen [::]:81;
             root /var/www/html;
        }
    server {
             listen 80;
             listen [::]:80;
             listen 2052;
             listen [::]:2052;
             listen 2082;
             listen [::]:2082;
             listen 2086;
             listen [::]:2086;
             listen 2095;
             listen [::]:2095;
             listen 8080;
             listen [::]:8080;
             listen 8880;
             listen [::]:8880;
             listen 443 ssl http2 reuseport;
             listen [::]:443 http2 reuseport;	
             listen 2053 ssl http2 reuseport;
             listen [::]:2053 http2 reuseport;	
             listen 2083 ssl http2 reuseport;
             listen [::]:2083 http2 reuseport;	
             listen 2087 ssl http2 reuseport;
             listen [::]:2087 http2 reuseport;	
             listen 2096 ssl http2 reuseport;
             listen [::]:2096 http2 reuseport;	
             listen 8443 ssl http2 reuseport;
             listen [::]:8443 http2 reuseport;	
             server_name $domain;
             ssl_certificate /etc/xray/xray.crt;
             ssl_certificate_key /etc/xray/xray.key;
             ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
             ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
             root /home/vps/public_html;
        }
EOF

sed -i '$ ilocation = /vless-ws' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:2001;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /vmess-ws' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:2002;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /trojan-ws' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:2003;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /socks-ws' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:2004;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation ^~ /vless-grpc' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:2005;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation ^~ /vmess-grpc' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:2006;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation ^~ /trojan-grpc' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:2007;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sed -i '$ ilocation = /' /etc/nginx/conf.d/xray.conf
sed -i '$ i{' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_pass http://127.0.0.1:2008;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/xray.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/xray.conf
sed -i '$ i}' /etc/nginx/conf.d/xray.conf

sleep 1
echo -e "[ ${green}INFO$NC ] Installing bbr.."
#wget -q -O /usr/bin/bbr "https://raw.githubusercontent.com/apih46/mini/main/dll/bbr.sh"
#chmod +x /usr/bin/bbr
#bbr >/dev/null 2>&1
#rm /usr/bin/bbr >/dev/null 2>&1
echo -e "$yell[SERVICE]$NC Restart All service"
systemctl daemon-reload
sleep 1
echo -e "[ ${green}ok${NC} ] Enable & restart xray "
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn
service nginx restart
service xray restart

# setting vnstat
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6

#done
clear
#rm -f ins-xray.sh
rm -f install-xray.sh

cd /usr/bin
# Download Main Menu
wget -O menu "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/menu.sh"
wget -O all-xray "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/all-xray.sh"
wget -O xraymod "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/xraymod.sh"
wget -O xrayofficial "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/xrayofficial.sh"
wget -O kernel-bbr "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/kernel-bbr.sh"
wget -O kernel-xanmod "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/kernel-xanmod.sh"
wget -O restart "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/restart.sh"
wget -O ganti-domain "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/ganti-domain.sh"
chmod +x menu
chmod +x all-xray
chmod +x xraymod
chmod +x xrayofficial
chmod +x kernel-bbr
chmod +x kernel-xanmod
chmod +x restart
chmod +x ganti-domain

# All
wget -O add-all "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/add-all.sh"
wget -O del-all "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/del-all.sh"
wget -O extend-all "https://raw.githubusercontent.com/ariefrahman10/RUNGKAD_V1/main/menu/extend-all.sh"
chmod +x add-all
chmod +x del-all
chmod +x extend-all
cd

clear
echo "==========================================================" | tee -a log-install.log
echo "" | tee -a log-install.log
echo "   >>> Service & Port" | tee -a log-install.log
echo "   - Vmess Websocket             : 443, 80" | tee -a log-install.log
echo "   - Vless Websocket             : 443" | tee -a log-install.log
echo "   - Trojan Websocket            : 443" | tee -a log-install.log
echo "   - Socks Websocket             : 443" | tee -a log-install.log
echo "   - Vmess gRPC                  : 443" | tee -a log-install.log
echo "   - Vless gRPC                  : 443" | tee -a log-install.log
echo "   - Trojan gRPC                 : 443" | tee -a log-install.log
echo "" | tee -a log-install.log
echo "   >>> Alternative Ports" | tee -a log-install.log
echo "   - HTTPS / TLS : 2053, 2083, 2087, 2096, 8443" | tee -a log-install.log
echo "   - HTTP        : 8080, 8880, 2052, 2082, 2086, 2095" | tee -a log-install.log
echo "" | tee -a log-install.log
echo "==========================================================" | tee -a log-install.log
echo ""
echo ""
rm -f install
secs_to_human "$(($(date +%s) - ${start}))"
echo -ne "[ WARNING ] reboot now ? (Y/N) "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
