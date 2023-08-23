FROM ubuntu:20.04 as base

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai
RUN apt-get update
RUN apt-get install -y tzdata
RUN apt-get install -y build-essential cmake vim python3.7 \
make autoconf automake libtool ninja-build libglib2.0-dev \
libfdt-dev libpixman-1-dev zlib1g-dev patchelf wget libattr1 libattr1-dev \
libcap-ng-dev pkg-config libvncserver-dev software-properties-common \
git libjpeg-dev libsasl2-dev libncurses5-dev libncursesw5-dev \
libgtk-3-dev libsdl2-dev screen parallel \
htop cpulimit meson autoconf-archive libopus-dev zip unzip sudo

RUN apt-get install -y curl
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python3 get-pip.py
RUN python3 -m pip install install wllvm picire gdown pyyaml

WORKDIR /root

# update binutils
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.35.tar.gz
RUN tar xzvf binutils-2.35.tar.gz; \
cd binutils-2.35; ./configure; make -j8; make install;
RUN rm /usr/bin/objcopy; ln -s /usr/local/bin/objcopy /usr/bin/objcopy

# update gdb
RUN apt-get install -y gdb
RUN wget -q -O ~/.gdbinit-gef.py https://raw.githubusercontent.com/hugsy/gef/main/gef.py
RUN echo source /root/.gdbinit-gef.py >> ~/.gdbinit
ENV LC_CTYPE=C.UTF-8

# virtualbox
RUN apt-get install -y acpica-tools chrpath doxygen g++-multilib libasound2-dev libcap-dev \
libcurl4-openssl-dev libdevmapper-dev libidl-dev libopus-dev libpam0g-dev \
libpulse-dev libqt5opengl5-dev libqt5x11extras5-dev qttools5-dev libsdl1.2-dev libsdl-ttf2.0-dev \
libssl-dev libvpx-dev libxcursor-dev libxinerama-dev libxml2-dev libxml2-utils \
libxmu-dev libxrandr-dev make nasm python3-dev qttools5-dev-tools \
unzip xsltproc default-jdk libstdc++5 libxslt1-dev linux-kernel-headers makeself \
mesa-common-dev subversion yasm zlib1g-dev
RUN apt-get install -y lib32z1 libc6-dev-i386 lib32gcc-s1 lib32stdc++6
RUN apt-get install -y pylint python3-psycopg2 python3-willow
RUN \
ln -s libX11.so.6    /usr/lib32/libX11.so && \
ln -s libXTrap.so.6  /usr/lib32/libXTrap.so && \
ln -s libXt.so.6     /usr/lib32/libXt.so && \
ln -s libXtst.so.6   /usr/lib32/libXtst.so && \
ln -s libXmu.so.6    /usr/lib32/libXmu.so && \
ln -s libXext.so.6   /usr/lib32/libXext.so
RUN apt-get install -y libcurl4-openssl-dev
RUN apt-get install -y libncurses5
RUN git config --global --add safe.directory '*'
Run apt-get install -y glslang-tools llvm
RUN apt-get install -y bison flex
RUN apt-get install -y libspice-protocol-dev libspice-server-dev

# fix missing slirp
RUN apt-get install -y libslirp-dev

FROM base as development

# update llvm toolchains
RUN python3 -m pip install --upgrade --no-cache-dir gdown \
    --disable-pip-version-check --root-user-action=ignore
RUN mkdir llvm-project
RUN cd llvm-project && gdown https://drive.google.com/uc?id=1bHHYPwpmFaEvhkNcZuCa_Fbk8A41IEJr && \
tar xf llvm-project-13.tar.gz && cd $OLDPWD
ENV PATH=/root/llvm-project/bin:$PATH
