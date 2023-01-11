#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Trojan Account           "
echo -e "========================================="
read -rp "User: " -e user
user_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${user_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Trojan Account           "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-trojan
fi
done

uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#trojanwsnon$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojangrpcnon$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojanws$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#trojangrpc$/a\#%& '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

trojanlink1="trojan://${uuid}@$domain:443?path=/trojan-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
trojanlink2="trojan://${uuid}@$domain:80?path=/trojan-wsnon&security=none&host=$domain&type=ws#$user"
trojanlink3="trojan://${uuid}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=trojan-grpc&sni=$domain#$user"
trojanlink4="trojan://${uuid}@$domain:80?security=none&encryption=none&type=grpc&serviceName=trojan-grpcnon&sni=$domain#$user"

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "             Trojan Account              " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks              : ${user}" | tee -a log-create-user.log
echo -e "Domain               : ${domain}" | tee -a log-create-user.log
echo -e "Port WS TLS          : 443" | tee -a log-create-user.log
echo -e "Port non TLS/HTTP    : 80" | tee -a log-create-user.log
echo -e "Password             : ${uuid}" | tee -a log-create-user.log
echo -e "Network              : Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path WS TLS          : /trojan-ws" | tee -a log-create-user.log
echo -e "Path WS non TLS      : /trojan-wsnon" | tee -a log-create-user.log
echo -e "ServiceName TLS      : trojan-grpc" | tee -a log-create-user.log
echo -e "ServiceName HTTP     : trojan-grpcnon" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $trojanlink1" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $trojanlink2" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $trojanlink3" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $trojanlink4" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
