#/bin/bash
#if needed ip route add 0.0.0.0/0 via 192.168.56.1
ifconfig eth0 192.168.56.101 netmask 255.255.255.0 up
route add default gw 192.168.56.1 dev eth0
ndc resolver setifdns eth0 8.8.8.8 8.8.4.4
ndc resolver setdefaultif eth0
export PYTHONHOME=/data/local/python
export PYTHONPATH=/data/local/python/extras:/data/local/python/lib/python2.7/lib-dynload:/data/local/python/lib/python2.7
export PATH=$PYTHONHOME/bin:$PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/data/local/python/lib:/data/local/python/lib/python2.7/lib-dynload
su -c "/data/local/agent.sh" & 