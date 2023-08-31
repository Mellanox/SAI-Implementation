#!/bin/bash

apt-get update
apt-get --yes install gawk
apt-get --yes install graphviz
apt-get --yes install doxygen
apt-get --yes install libxml-simple-perl
apt-get --yes install aspell
apt-get --yes install aspell-en
apt-get --yes install dos2unix
apt-get --yes install g++
apt-get --yes install libevent-dev
#install libssl
wget http://deb.debian.org/debian/pool/main/o/openssl1.0/libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb
sudo dpkg -i libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb
apt-get --yes install libboost-all-dev
apt-get install fuse3 libfuse3-3 libfuse3-dev
#perl -MCPAN -e'install "LWP::Simple"'
chmod 777 /usr/lib/pkgconfig/
chmod 777 /usr/bin/
chmod 777 /usr/lib/
chmod 777 /usr/share/
chmod 777 /usr/include/sai/
chmod 777 /usr/include/

cd /var
git clone https://github.com/davidjamesca/ctypesgen
cd ctypesgen
git checkout 1.1.1
python3.9 setup.py install &>/dev/null
cd ..

sudo dpkg -i --force-overwrite /auto/mswg/release/sx_mlnx_os/sai/thrift_0.17.0-1_linux7-64.deb
pip3.9 install thrift
patch /usr/lib/python3.9/site-packages/thrift/compat.py < /auto/mswg/release/sx_mlnx_os/sai/thrift_patch.patch

# install MARS ver_tools
sudo echo "export PYTHONPATH=\"/opt/ver_sdk\":\"\$PYTHONPATH\"" >> ~/.bashrc
sudo python /auto/mswg/projects/ver_tools/sdk_exe_folder/install_ver_tools.py --install_pointer reg2_beta --ignore_packages scapy,setuptools,kvl,vl

ldconfig
