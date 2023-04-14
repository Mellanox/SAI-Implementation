#!/usr/bin/env bash

# installation script for MARS servers for ptf tests

#install python3.9, pip3 and link python3->python3.9
yum update -y
sudo yum install wget -y
wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tgz
tar xvf Python-3.9.13.tgz
sudo tar xvf Python-3.9.13.tgz
cd Python-3.9*/
./configure --enable-optimizations
sudo make altinstall -j$(nproc)
/usr/local/bin/python3.9 -m pip install --upgrade pip
ln -s /usr/local/bin/python3.9 /usr/bin/python3

#remove MARS ver-tools old scapy 2.2.0 from /opt/ver_sdk
rm -rfv /opt/ver_sdk/bin/scapy
rm -rf /opt/ver_sdk/setuptools-0.6c11-py2.7.egg #(package dependency suitable for python2)

#install new scapy 2.4.5
pip3 install setuptools
cd /var
git clone https://github.com/secdev/scapy
cd scapy/
git checkout v2.4.5
python3 setup.py install

#install new thrift
cd /var
git clone https://github.com/apache/thrift.git
cd thrift
git checkout v0.17.0
./bootstrap.sh && ./configure -q --prefix=/usr --disable-tests --with-kotlin=no --with-python=no
make -j$(nproc)
make install -j$(nproc)
cd lib/py
python3 setup.py install
patch /usr/local/lib/python3.9/site-packages/thrift-0.17.0-py3.9-linux-x86_64.egg/thrift/compat.py < /auto/mswg/release/sx_mlnx_os/sai/thrift_patch.patch
