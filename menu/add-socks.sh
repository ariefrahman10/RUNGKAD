#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Socks5 Account           "
echo -e "========================================="
read -rp "Username: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Socks5 Account           "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-socks
fi
done

until [[ $pass =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
read -rp "Password: " -e pass
CLIENT_EXISTS=$(grep -w $pass /usr/local/etc/xray/config.json | wc -l)
if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Socks5 Account           "
echo -e "========================================="
echo -e ""
echo -e "A client with the specified name was already created, please choose another name."
echo -e ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-socks
clear
fi
done

read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#sockswsnon$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socksgrpcnon$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socksws$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#socksgrpc$/a\#%& '"$user $exp"'\
},{"user": "'""$user""'","pass": "'""$pass""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

echo -n "$user:$pass" | base64 > /tmp/log
socks_base64=$(cat /tmp/log)
sockslink1="socks://$socks_base64@$domain:443?path=/socks-ws&security=tls&host=$domain&type=ws&sni=$domain#$user"
sockslink2="socks://$socks_base64@$domain:80?path=/socks-wsnon&security=none&host=$domain&type=ws#$user"
sockslink3="socks://$socks_base64@$domain:443?security=tls&encryption=none&type=grpc&serviceName=socks-grpc&sni=$domain#$user"
sockslink4="socks://$socks_base64@$domain:80?security=none&encryption=none&type=grpc&serviceName=socks-grpcnon&sni=$domain#$user"
rm -rf /tmp/log

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "              Socks5 Account            " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Username         	: ${user}" | tee -a log-create-user.log
echo -e "Password         	: ${pass}" | tee -a log-create-user.log
echo -e "Domain           	: ${domain}" | tee -a log-create-user.log
echo -e "Port TLS         	: 443" | tee -a log-create-user.log
echo -e "Port none TLS    	: 80" | tee -a log-create-user.log
echo -e "Network          	: Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path WS TLS   		: /socks-ws" | tee -a log-create-user.log
echo -e "Path WS non TLS    : /socks-wsnon" | tee -a log-create-user.log
echo -e "ServiceName TLS    : socks-grpc" | tee -a log-create-user.log
echo -e "ServiceName HTTP   : socks-grpcnon" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $sockslink1" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $sockslink2" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $sockslink3" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $sockslink4" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
