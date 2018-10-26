TODO


sudo ip link add pt0 type bridge
sudo ip addr add 192.168.56.1/24 dev pt0
sudo ip link set pt0 up

-device e1000,netdev=net0,mac=98:de:d0:04:cb:ff -netdev tap,id=net0,script=qemu-ifup

Note, will need to set static IP address
