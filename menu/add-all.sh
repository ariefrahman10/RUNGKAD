#!/bin/bash

clear
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "=========================================================="
echo -e "                [  Create All Account  ]                  "
echo -e "              Vmess, Vless, Trojan, Socks5                "
echo -e "=========================================================="
read -rp "Username: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)
if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "=========================================================="
echo -e "                [  Create All Account  ]                  "
echo -e "=========================================================="
echo -e ""
echo -e "A client with the specified name was already created, please choose another name."
echo -e ""
echo -e "=========================================================="
read -n 1 -s -r -p "Press any key to back on menu"
all-xray
clear
fi
done

until [[ $pass =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
read -rp "Password (Pass for Socks5): " -e pass
CLIENT_EXISTS=$(grep -w $pass /usr/local/etc/xray/config.json | wc -l)
if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "=========================================================="
echo -e "                [  Create All Account  ]                  "
echo -e "=========================================================="
echo -e ""
echo -e "A client with the specified name was already created, please choose another name."
echo -e ""
echo -e "=========================================================="
read -n 1 -s -r -p "Press any key to back on menu"
all-xray
clear
fi
done

domain=$(cat /usr/local/etc/xray/domain)
uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#vmess$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vless$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojan$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socks$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

sed -i '/#vmess-grpc$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vless-grpc$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojan-grpc$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

sed -i '/#vmessnontls$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$user""'"' /usr/local/etc/xray/config.json

vmlink1=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "443",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/vmess-ws",
      "type": "none",
      "host": "$domain",
      "tls": "tls"
}
EOF`
vmlink2=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "80",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/multipath",
      "type": "none",
      "host": "$domain",
      "tls": "none"
}
EOF`
vmlink3=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "443",
      "id": "${uuid}",
      "aid": "0",
      "net": "grpc",
      "path": "vmess-grpc",
      "type": "none",
      "host": "$domain",
      "tls": "tls"
}
EOF`
vmesslink1="vmess://$(echo $vmlink1 | base64 -w 0)"
vmesslink2="vmess://$(echo $vmlink2 | base64 -w 0)"
vmesslink3="vmess://$(echo $vmlink3 | base64 -w 0)"

vlesslink1="vless://$uuid@$domain:443?path=/vless-ws&security=tls&encryption=none&host=$domain&type=ws&sni=$domain#$user"
vlesslink2="vless://$uuid@$domain:443?security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$domain#$user"

trojanlink1="trojan://$uuid@$domain:443?path=/trojan-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
trojanlink2="trojan://${uuid}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=trojan-grpc&sni=$domain#$user"

echo -n "$user:$pass" | base64 > /tmp/log
socks_base64=$(cat /tmp/log)
sockslink1="socks://$socks_base64@$domain:443?path=/socks-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"

systemctl restart xray
clear
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                   [ All Account VPN ]                    " | tee -a log-create-user.log
echo -e "                  Vmess, Vless, Trojan                    " | tee -a log-create-user.log
echo -e "          Shadowsocks 2022, Shadowsocks, Socks5           " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Domain           : $domain" | tee -a log-create-user.log
echo -e "Port TLS         : 443" | tee -a log-create-user.log
echo -e "Port non TLS     : 80" | tee -a log-create-user.log
echo -e "Alt Port TLS     : 2053, 2083, 2087, 2096, 8443" | tee -a log-create-user.log
echo -e "Alt Port non TLS : 8080, 8880, 2052, 2082, 2086 2095" | tee -a log-create-user.log
echo -e "Username Socks5  : $user" | tee -a log-create-user.log
echo -e "Password Socks5  : $pass" | tee -a log-create-user.log
echo -e "Network          : Websocket, gRPC" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                   ---[ Vmess Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link TLS      : $vmesslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link non TLS  : $vmesslink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC     : $vmesslink3" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                   ---[ Vless Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link TLS      : $vlesslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC     : $vlesslink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                  ---[ Trojan Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link TLS      : $trojanlink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC     : $trojanlink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                  ---[ Socks5 Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link TLS      : $sockslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Expired On    : $exp" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu" | tee -a log-create-user.log
clear
menu
