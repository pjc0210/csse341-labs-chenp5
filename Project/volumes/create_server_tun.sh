#!/bin/bash


echo -e -n 'Adding the tun device: '
if ip tuntap add mode tun dev tun0 ; then
  echo -e 'Ok.'
else
  echo -e 'Failed.'
  exit 1
fi

echo -e -n 'Assigning tun device static IPv4 address: '
if ip addr add 192.168.133.6 dev tun0 ; then
  echo -e 'Ok.'
else
  echo -e 'Failed.'
  exit 1
fi

echo -e -n 'Bringing tun device up: '
if ip link set dev tun0 up ; then
  echo -e 'Ok.'
else
  echo -e 'Failed.'
  exit 1
fi

echo -e -n 'Setting up routing: '
if ip route add 192.168.133.128/25 dev tun0 ; then
  echo -e 'Ok.'
else
  echo -e 'Failed.'
  exit 1
fi
