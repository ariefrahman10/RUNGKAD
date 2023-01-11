#!/bin/bash

xray_service=$(systemctl status xray | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
nginx_service=$(systemctl status nginx | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
# STATUS SERVICE XRAY 
if [[ $xray_service == "running" ]]; then 
   status_xray="[ ON ] Running"
else
   status_xray="[ OFF ] Not Running"
fi
# STATUS SERVICE NGINX 
if [[ $nginx_service == "running" ]]; then 
   status_nginx="[ ON ] Running"
else
   status_nginx="[ OFF ] Not Running"
fi

domain=$(cat /usr/local/etc/xray/domain)
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
CITY=$(curl -s ipinfo.io/city)
WKT=$(curl -s ipinfo.io/timezone)
DATE=$(date -R | cut -d " " -f -4)
MYIP=$(curl -sS ipv4.icanhazip.com)
clear 
echo "========================================="
echo "              [ RUNGKAD ]                "
echo "========================================="
echo " Operating System  : "`hostnamectl | grep "Operating System" | cut -d ' ' -f5-`
echo " IP Address        : $MYIP"	
echo " Service Provider  : $ISP"
echo " Timezone          : $WKT"
echo " City              : $CITY"
echo " Domain            : $domain"	
echo " Date              : $DATE"	
echo "========================================="
echo "  NGINX STATUS : $status_nginx"
echo "  XRAY STATUS  : $status_xray"
echo "========================================="
echo "              [ RUNGKAD ]                "
echo "========================================="
echo "   1 ] Vmess Menu"
echo "   2 ] Vless Menu"
echo "   3 ] Trojan Menu"
echo "   4 ] Shadowsocks 2022 Menu"
echo "   5 ] Socks5 Menu"
echo "   6 ] Create All Account"
echo "   7 ] Change Xray-core Mod"
echo "   8 ] Change Xray-core Official"
echo "   9 ] Update kernel + TCP BBR"
echo "  10 ] Update kernel XanMod"
echo "  11 ] Restart All Service"
echo "  12 ] Change Domain"
echo ""
echo " Press X or [ Ctrl + C ] To Exit Script"
echo ""
echo "========================================="
echo ""
read -p " Select Menu :  "  opt
echo ""
case $opt in
1) clear ; m-vmess ;;
2) clear ; m-vless ;;
3) clear ; m-trojan ;;
4) clear ; m-ss ;;
5) clear ; m-socks ;;
6) clear ; all-xray ;;
7) clear ; xraymod ;;
8) clear ; xrayofficial ;;
9) clear ; kernel-bbr ;;
10) clear ; kernel-xanmod ;;
11) clear ; restart ;;
12) clear ; ganti-domain ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; menu ;;
esac
