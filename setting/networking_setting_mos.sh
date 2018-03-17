#!/bin/sh

sudo ifconfig dpdk0 192.168.1.2 netmask 255.255.255.0
sudo ifconfig dpdk1 192.168.2.2 netmask 255.255.255.0
