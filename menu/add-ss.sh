#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "       Add Shadowsocks 2022 Account      "
echo -e "========================================="
read -rp "User: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "       Add Shadowsocks 2022 Account      "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-ss22
fi
done

cipher="2022-blake3-aes-128-gcm"
userpsk=$(openssl rand -base64 16)
serverpsk=$(cat /usr/local/etc/xray/serverpsk)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`

sed -i '/#ss-ws$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#ss-wsnon$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#ss-grpc$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#ss-grpcnon$/a\#% '"$user $exp"'\
},{"password": "'""$userpsk""'","method": "'""$cipher""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

echo -n "$cipher:$serverpsk:$userpsk" | base64 -w 0 > /tmp/log
ss_base64=$(cat /tmp/log)
sslink1="ss://${ss_base64}@$domain:443?path=/ss-ws&security=tls&host=${domain}&type=ws&sni=${domain}#${user}"
sslink2="ss://${ss_base64}@$domain:80?path=/ss-wsnon&security=none&host=${domain}&type=ws#${user}"
sslink3="ss://${ss_base64}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=ss-grpc&sni=$domain#${user}"
sslink4="ss://${ss_base64}@$domain:80?security=none&encryption=none&type=grpc&serviceName=ss-grpcnon&sni=$domain#${user}"
rm -rf /tmp/log

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "           Shadowsocks Account           " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks          	: ${user}" | tee -a log-create-user.log
echo -e "Domain           	: ${domain}" | tee -a log-create-user.log
echo -e "Port TLS        	: 443" | tee -a log-create-user.log
echo -e "Port none TLS    	: 80" | tee -a log-create-user.log
echo -e "Port gRPC       	: 443" | tee -a log-create-user.log
echo -e "Cipher           	: ${cipher}" | tee -a log-create-user.log
echo -e "Password         	: $serverpsk:$userpsk" | tee -a log-create-user.log
echo -e "Network          	: Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path WS TLS      	: /ss-ws" | tee -a log-create-user.log
echo -e "Path WS non TLS    : /ss-wsnon" | tee -a log-create-user.log
echo -e "ServiceName TLS    : ss-grpc" | tee -a log-create-user.log
echo -e "ServiceName HTTP   : ss-grpcnon" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $sslink1" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $sslink2" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $sslink3" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $sslink4" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
