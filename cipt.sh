#!/bin/ash

# This little script clears iptables after danish.py fails terribly

IPT=/usr/sbin/iptables
IPT6=/usr/sbin/ip6tables

$IPT --list|grep -i danish
$IPT6 --list|grep -i danish
$IPT -D FORWARD -j danish
$IPT6 -D FORWARD -j danish
$IPT -F danish
$IPT6 -F danish
$IPT -X danish
$IPT6 -X danish

echo "Anything left?"
$IPT --list|grep -i danish
$IPT6 --list|grep -i danish
