#!/bin/bash

apt-get --yes install gawk
apt-get --yes install graphviz
apt-get --yes install doxygen
apt-get --yes install libxml-simple-perl
apt-get --yes install aspell
apt-get --yes install dos2unix
apt-get --yes install g++
apt-get --yes install libevent-dev
apt-get --yes install libssl1.0-dev
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

