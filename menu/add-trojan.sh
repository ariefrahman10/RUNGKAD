#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Trojan Account           "
echo -e "========================================="
read -rp "User: " -e user
user_EXISTS=$(grep -w $user /usr/local/etc/xray/trojanwstls.json && grep -w $user /usr/local/etc/xray/trojangrpc.json | wc -l)


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

read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#trojanws$/a\#& '"$user $exp"'\
},{"password": "'""$user""'","email": "'""$user""'"' /usr/local/etc/xray/trojanwstls.json
sed -i '/#trojangrpc$/a\#& '"$user $exp"'\
},{"password": "'""$user""'","email": "'""$user""'"' /usr/local/etc/xray/trojangrpc.json

trojanlink1="trojan://${user}@$domain:443?path=/trojan-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
trojanlink2="trojan://${user}@$domain:443?security=tls&encryption=none&type=grpc&serviceName=trojangrpc&sni=$domain#$user"

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "             Trojan Account             " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks          : ${user}" | tee -a log-create-user.log
echo -e "Host/IP          : ${domain}" | tee -a log-create-user.log
echo -e "Wildcard         : (bug.com).${domain}" | tee -a log-create-user.log
echo -e "Port TLS         : 443" | tee -a log-create-user.log
echo -e "Port gRPC        : 443" | tee -a log-create-user.log
echo -e "Password         : ${user}" | tee -a log-create-user.log
echo -e "Network          : Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path Websocket   : /trojan-ws" | tee -a log-create-user.log
echo -e "ServiceName      : trojangrpc" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link TLS       : ${trojanlink1}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC      : ${trojanlink2}" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
