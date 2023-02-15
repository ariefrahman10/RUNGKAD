#!/bin/bash

clear
NUMBER_OF_CLIENTS=$(grep -c -E "^#%& " "/usr/local/etc/xray/config.json")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
echo -e "========================================="
echo -e "               Delete User               "
echo -e "========================================="
echo -e ""
echo -e "You have no existing clients!"
echo -e ""
echo -e "========================================="
read -n 1 -s -r -p "Press any key to back on menu"
menu
fi

clear
echo -e "========================================="
echo -e "               Delete User               "
echo -e "========================================="
echo -e "  User       Expired  " 
echo -e "========================================="
grep -E "^#%& " "/usr/local/etc/xray/config.json" | cut -d ' ' -f 2-3 | column -t | sort | uniq
echo -e ""
echo -e "tap enter to go back"
echo -e "========================================="
read -rp "Input Username : " user
if [ -z $user ]; then
menu
else
exp=$(grep -wE "^#%& $user" "/usr/local/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#%& $user $exp/,/^},{/d" /usr/local/etc/xray/config.json

systemctl restart xray
clear
echo -e "========================================="
echo -e "        User Deleted Successfully        "
echo -e "========================================="
echo -e " Client Name : $user"
echo -e " Expired On  : $exp"
echo -e "========================================="
echo -e ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
fi
