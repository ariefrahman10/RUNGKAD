#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Vless Account            "
echo -e "========================================="
read -rp "User: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Vless Account            "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
add-vless
fi
done

uuid=$(cat /proc/sys/kernel/random/uuid)
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

vlesslink1="vless://$uuid@$domain:443?path=/vless-ws&security=tls&encryption=none&host=$domain&type=ws&sni=$domain#$user"
vlesslink2="vless://$uuid@$domain:80?path=/vless-wsnon&security=none&encryption=none&host=$domain&type=ws#$user"
vlesslink3="vless://$uuid@$domain:443?security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$domain#$user"
vlesslink4="vless://$uuid@$domain:80?security=none&encryption=none&type=grpc&serviceName=vless-grpcnon&sni=$domain#$user"

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "              Vless Account              " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks          	: ${user}" | tee -a log-create-user.log
echo -e "Domain           	: ${domain}" | tee -a log-create-user.log
echo -e "Port WS TLS      	: 443" | tee -a log-create-user.log
echo -e "Port non TLS/HTTP 	: 80" | tee -a log-create-user.log
echo -e "id               	: ${uuid}" | tee -a log-create-user.log
echo -e "Encryption       	: none" | tee -a log-create-user.log
echo -e "Network          	: Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path WS TLS      	: /vless-ws" | tee -a log-create-user.log
echo -e "Path WS non TLS  	: /vless-wsnon" | tee -a log-create-user.log
echo -e "ServiceName TLS 	: vless-grpc" | tee -a log-create-user.log
echo -e "ServiceName HTTP 	: vless-grpcnon" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $vlesslink1" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $vlesslink2" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $vlesslink3" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $vlesslink4" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
