#!/bin/bash

clear
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "=========================================================="
echo -e "                [  Create All Account  ]                  "
echo -e "                  Vmess, Vless, Trojan                    "
echo -e "                Shadowsocks 2022, Socks5                  "
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
cipher="2022-blake3-aes-128-gcm"
userpsk=$(openssl rand -base64 16)
uuid=$(cat /proc/sys/kernel/random/uuid)
serverpsk=$(cat /usr/local/etc/xray/serverpsk)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`

sed -i '/#vlesswsnon$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vlessgrpcnon$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vlessws$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vlessgrpc$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

sed -i '/#vmesswsnon$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vmessgrpcnon$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vmessws$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vmessgrpc$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

sed -i '/#trojanwsnon$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojangrpcnon$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojanws$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojangrpc$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

sed -i '/#ssws$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#sswsnon$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#ssgrpc$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#ssgrpcnon$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

sed -i '/#sockswsnon$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socksgrpcnon$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socksws$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socksgrpc$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json


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
      "path": "/vmess-wsnon",
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
vmlink4=`cat<<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "80",
      "id": "${uuid}",
      "aid": "0",
      "net": "grpc",
      "path": "vmess-grpcnon",
      "type": "none",
      "host": "$domain",
      "tls": "none"
}
EOF`
vmesslink1="vmess://$(echo $vmlink1 | base64 -w 0)"
vmesslink2="vmess://$(echo $vmlink2 | base64 -w 0)"
vmesslink3="vmess://$(echo $vmlink3 | base64 -w 0)"
vmesslink4="vmess://$(echo $vmlink4 | base64 -w 0)"

vlesslink1="vless://$uuid@$domain:443?path=/vless-ws&security=tls&encryption=none&host=$domain&type=ws&sni=$domain#$user"
vlesslink2="vless://$uuid@$domain:80?path=/vless-wsnon&security=none&encryption=none&host=$domain&type=ws#$user"
vlesslink3="vless://$uuid@$domain:443?security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$domain#$user"
vlesslink4="vless://$uuid@$domain:80?security=none&encryption=none&type=grpc&serviceName=vless-grpcnon&sni=$domain#$user"

trojanlink1="trojan://${uuid}@$domain:443?path=/trojan-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
trojanlink2="trojan://${uuid}@$domain:80?path=/trojan-wsnon&security=none&host=$domain&type=ws#$user"
trojanlink3="trojan://${uuid}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=trojan-grpc&sni=$domain#$user"
trojanlink4="trojan://${uuid}@$domain:80?security=none&encryption=none&type=grpc&serviceName=trojan-grpcnon&sni=$domain#$user"

echo -n "$cipher:$serverpsk:$userpsk" | base64 -w 0 > /tmp/log
ss_base64=$(cat /tmp/log)
sslink1="ss://${ss_base64}@$domain:443?path=/ss-ws&security=tls&host=${domain}&type=ws&sni=${domain}#${user}"
sslink2="ss://${ss_base64}@$domain:80?path=/ss-wsnon&security=none&host=${domain}&type=ws#${user}"
sslink3="ss://${ss_base64}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=ss-grpc&sni=$domain#${user}"
sslink4="ss://${ss_base64}@$domain:80?security=none&encryption=none&type=grpc&serviceName=ss-grpcnon&sni=$domain#${user}"
rm -rf /tmp/log

echo -n "$user:$pass" | base64 > /tmp/log
socks_base64=$(cat /tmp/log)
sockslink1="socks://$socks_base64@$domain:443?path=/socks-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
sockslink2="socks://$socks_base64@$domain:80?path=/socks-wsnon&security=none&host=$domain&type=ws#$user"
sockslink3="socks://$socks_base64@$domain:443?security=tls&encryption=none&type=grpc&serviceName=socks-grpc&sni=$domain#$user"
sockslink4="socks://$socks_base64@$domain:80?security=none&encryption=none&type=grpc&serviceName=socks-grpcnon&sni=$domain#$user"
rm -rf /tmp/log

systemctl restart xray
clear
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                   [ All Account VPN ]                    " | tee -a log-create-user.log
echo -e "                  Vmess, Vless, Trojan                    " | tee -a log-create-user.log
echo -e "                   Shadowsocks, Socks5                    " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Domain             : $domain" | tee -a log-create-user.log
echo -e "Port WS TLS        : 443" | tee -a log-create-user.log
echo -e "Port non TLS/HTTP  : 80" | tee -a log-create-user.log
echo -e "Cipher SS          : $cipher" | tee -a log-create-user.log
echo -e "UUID/Password      : $uuid" | tee -a log-create-user.log
echo -e "Pass SS            : $serverpsk:$userpsk" | tee -a log-create-user.log
echo -e "Username Socks5    : $user" | tee -a log-create-user.log
echo -e "Password Socks5    : $pass" | tee -a log-create-user.log
echo -e "Network            : Websocket, gRPC" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                   ---[ Vmess Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $vmesslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $vmesslink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $vmesslink3" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $vmesslink4" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                   ---[ Vless Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $vlesslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $vlesslink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $vlesslink3" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $vlesslink4" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                  ---[ Trojan Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $trojanlink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $trojanlink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $trojanlink3" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $trojanlink4" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                ---[ Shadowsocks Link ]---                " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $sslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $sslink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $sslink3" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $sslink4" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "[X]" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "                  ---[ Socks5 Link ]---                   " | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $sockslink1" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $sockslink2" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $sockslink3" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $sockslink4" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
echo -e "Expired On    : $exp" | tee -a log-create-user.log
echo -e "==========================================================" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu" | tee -a log-create-user.log
clear
menu
