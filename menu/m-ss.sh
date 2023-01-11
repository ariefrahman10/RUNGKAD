#!/bin/bash

clear
echo -e "========================================="
echo -e "      [ • Shadowsocks 2022 Menu • ]      "
echo -e "========================================="
echo -e ""
echo -e " [ 1 ] Create Account Shadowsocks 2022 "
echo -e " [ 2 ] Extending Account Shadowsocks 2022 "
echo -e " [ 3 ] Delete Account Shadowsocks 2022 "
echo -e " [ 0 ] Back To Menu"
echo -e ""
echo -e " Press X or [ Ctrl + C ] To Exit"
echo ""
echo -e "========================================="
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
1) clear ; add-ss ;;
2) clear ; extend-ss ;;
3) clear ; del-ss ;;
0) clear ; menu ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; m-ss22 ;;
esac
