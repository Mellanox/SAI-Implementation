#!/bin/bash

apt-get update
apt-get --yes install gawk
apt-get --yes install graphviz
apt-get --yes install doxygen
apt-get --yes install libxml-simple-perl
apt-get --yes install aspell
apt-get --yes install dos2unix
apt-get --yes install g++
apt-get --yes install libevent-dev
#install libssl
wget http://deb.debian.org/debian/pool/main/o/openssl1.0/libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb
sudo dpkg -i libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb
apt-get --yes install libboost-all-dev
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
git checkout 3d2d9803339503d2988382aa861b47a6a4872c32
git apply /auto/mswg/release/sx_mlnx_os/sai/ctypesgen_patch.patch
python setup.py install &>/dev/null
cd ..

sudo dpkg -i --force-overwrite /auto/mswg/release/sx_mlnx_os/sai/thrift_0.9.2-1_linux7-64.deb
pip install thrift

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

ldconfig

git clone https://github.com/nanomsg/nnpy.git
cd nnpy
sudo pip2 install .
cd ..
sudo pip2 install psutil
sudo pip2 install cffi
sudo pip2 install --upgrade cffi
