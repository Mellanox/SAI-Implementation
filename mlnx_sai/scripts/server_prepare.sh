#!/usr/bin/env bash

# installation script for MARS servers for ptf tests

#install python3.9, pip3 and link python3->python3.9
cd /var
yum update -y
sudo yum install wget -y
wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tgz
sudo tar xvf Python-3.9.13.tgz
cd Python-3.9*/
sudo ./configure --enable-optimizations
sudo make altinstall -j$(nproc)
sudo /usr/local/bin/python3.9 -m pip install --upgrade pip
sudo ln -sf /usr/local/bin/python3.9 /usr/bin/python3

#remove MARS ver-tools old scapy 2.2.0 from /opt/ver_sdk
sudo rm -rfv /opt/ver_sdk/bin/scapy /opt/ver_sdk/scapy
sudo rm -rf /opt/ver_sdk/setuptools-0.6c11-py2.7.egg #(package dependency suitable for python2)

#install new scapy 2.4.5
sudo pip3 install setuptools
cd /var
git clone https://github.com/secdev/scapy
cd scapy/
git checkout v2.4.5
sudo python3 setup.py install

#install new thrift
cd /var
git clone https://github.com/apache/thrift.git
cd thrift
git checkout v0.17.0
sudo ./bootstrap.sh && sudo ./configure -q --prefix=/usr --disable-tests --with-kotlin=no --with-python=no
sudo make -j$(nproc)
sudo make install -j$(nproc)
cd lib/py
sudo python3 setup.py install
sudo patch /usr/local/lib/python3.9/site-packages/thrift-0.17.0-py3.9-linux-x86_64.egg/thrift/compat.py < /auto/mswg/release/sx_mlnx_os/sai/thrift_patch.patch

# install MARS ver_tools
sudo echo "export PYTHONPATH=\"/opt/ver_sdk\":\"\$PYTHONPATH\"" >> ~/.bashrc
sudo python /auto/mswg/projects/ver_tools/sdk_exe_folder/install_ver_tools.py --install_pointer reg2_beta --ignore_packages scapy,setuptools,kvl,vl

# inxtall nanomsg
cd /var
wget https://github.com/nanomsg/nanomsg/archive/refs/tags/1.0.0.tar.gz
tar -xvf 1.0.0.tar.gz
cd nanomsg-1.0.0
mkdir build
cd build
cmake ..
cmake --build .
ctest -G Debug .
cmake --build . --target install
cd ..
cp -rf /usr/local/lib64/libnanomsg.so.5.0.0 /usr/local/lib64/libnanomsg.so.1.0.0 /usr/local/lib64/libnanomsg.so /usr/lib64

# adjust interfaces
ifconfig ens5 mtu 1700
ifconfig ens6 mtu 1700
ifconfig ens7 mtu 1700
ifconfig ens8 mtu 1700
ifconfig ens9 mtu 1700
ifconfig ens10 mtu 1700

ethtool -K ens5 txvlan off
ethtool -K ens6 txvlan off
ethtool -K ens7 txvlan off
ethtool -K ens8 txvlan off
ethtool -K ens9 txvlan off
ethtool -K ens10 txvlan off

ethtool -K ens5 rxvlan off
ethtool -K ens6 rxvlan off
ethtool -K ens7 rxvlan off
ethtool -K ens8 rxvlan off
ethtool -K ens9 rxvlan off
ethtool -K ens10 rxvlan off

