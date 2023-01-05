#!/bin/bash

bash <(curl -fsSL git.io/warp.sh) proxy

echo "[ INFO ] Install and automatically configure the Proxy Mode feature of the WARP client"
echo "[ INFO ] Enable the local loopback port 40000"
echo "[ INFO ] and use an application that supports SOCKS5 to connect to this port"
echo -e "Back to menu in 1 sec "
sleep 1
menu

