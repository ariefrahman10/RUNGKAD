#!/bin/bash

clear
domain=$(cat /usr/local/etc/xray/domain)
until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
echo -e "========================================="
echo -e "            Add Vmess Account            "
echo -e "========================================="
read -rp "User: " -e user
CLIENT_EXISTS=$(grep -w $user /usr/local/etc/xray/config.json | wc -l)

if [[ ${CLIENT_EXISTS} == '1' ]]; then
clear
echo -e "========================================="
echo -e "            Add Vmess Account            "
echo -e "========================================="
echo ""
echo "A client with the specified name was already created, please choose another name."
echo ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
add-vmess
fi
done

uuid=$(cat /proc/sys/kernel/random/uuid)
read -p "Expired (days): " masaaktif
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#vmesswsnon$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vmessgrpcnon$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vmessws$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json
sed -i '/#vmessgrpc$/a\#%& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/config.json

vlink1=`cat<<EOF
      {
      "v": "2",
      "ps": "$user",
      "add": "$domain",
      "port": "443",
      "id": "$uuid",
      "aid": "0",
      "net": "ws",
      "path": "/vmess-ws",
      "type": "none",
      "host": "$domain",
      "tls": "tls"
}
EOF`
vlink2=`cat<<EOF
      {
      "v": "2",
      "ps": "$user",
      "add": "$domain",
      "port": "80",
      "id": "$uuid",
      "aid": "0",
      "net": "ws",
      "path": "/vmess-wsnon",
      "type": "none",
      "host": "$domain",
      "tls": "none"
}
EOF`
vlink3=`cat<<EOF
      {
      "v": "2",
      "ps": "$user",
      "add": "$domain",
      "port": "443",
      "id": "$uuid",
      "aid": "0",
      "net": "grpc",
      "path": "vmess-grpc",
      "type": "none",
      "host": "$domain",
      "tls": "tls"
}
EOF`
vlink4=`cat<<EOF
      {
      "v": "2",
      "ps": "$user",
      "add": "$domain",
      "port": "80",
      "id": "$uuid",
      "aid": "0",
      "net": "grpc",
      "path": "vmess-grpcnon",
      "type": "none",
      "host": "$domain",
      "tls": "none"
}
EOF`

vmesslink1="vmess://$(echo $vlink1 | base64 -w 0)"
vmesslink2="vmess://$(echo $vlink2 | base64 -w 0)"
vmesslink3="vmess://$(echo $vlink3 | base64 -w 0)"
vmesslink4="vmess://$(echo $vlink4 | base64 -w 0)"

systemctl restart xray
clear
echo -e "=========================================" | tee -a log-create-user.log
echo -e "              Vmess Account              " | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Remarks              : ${user}" | tee -a log-create-user.log
echo -e "Domain               : ${domain}" | tee -a log-create-user.log
echo -e "Port WS TLS          : 443" | tee -a log-create-user.log
echo -e "Port non TLS/HTTP    : 80" | tee -a log-create-user.log
echo -e "id                   : ${uuid}" | tee -a log-create-user.log
echo -e "Encryption           : none" | tee -a log-create-user.log
echo -e "Network              : Websocket, gRPC" | tee -a log-create-user.log
echo -e "Path WS TLS          : /vmess-ws" | tee -a log-create-user.log
echo -e "Path WS non TLS      : /vmess-wsnon" | tee -a log-create-user.log
echo -e "ServiceName TLS      : vmess-grpc" | tee -a log-create-user.log
echo -e "ServiceName HTTP     : vmess-grpcnon" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS TLS        : $vmesslink1" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link WS non TLS    : $vmesslink2" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC TLS      : $vmesslink3" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Link gRPC non TLS  : $vmesslink4" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo -e "Expired On     : $exp" | tee -a log-create-user.log
echo -e "=========================================" | tee -a log-create-user.log
echo "" | tee -a log-create-user.log
read -n 1 -s -r -p "Press any key to back on menu"
clear
menu
