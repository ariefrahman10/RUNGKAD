#!/bin/bash

clear
echo -e "========================================="
echo -e "              [ • Menu • ]               "
echo -e "========================================="
echo -e ""
echo -e " [ 1 ] Create All Account "
echo -e " [ 2 ] Extending All Account "
echo -e " [ 3 ] Delete All Account "
echo -e " [ 0 ] Back To Menu"
echo -e ""
echo -e " Press X or [ Ctrl + C ] To Exit"
echo ""
echo -e "========================================="
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
1) clear ; add-all ;;
2) clear ; extend-all ;;
3) clear ; del-all ;;
0) clear ; menu ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; all-xray ;;
esac
