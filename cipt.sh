#!/bin/ash

# This little script clears iptables after danish.py fails terribly

IPT=/usr/sbin/iptables

$IPT --list|grep -i danish

$IPT -D FORWARD -j danish
$IPT -F danish
$IPT -X danish


echo "Anything left?"
$IPT --list|grep -i danish
