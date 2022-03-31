FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install -y build-essential cmake vim python3.7 \
make autoconf automake libtool ninja-build libglib2.0-dev \
libfdt-dev libpixman-1-dev zlib1g-dev patchelf wget libattr1 libattr1-dev \
libcap-ng-dev pkg-config libvncserver-dev software-properties-common \
git libjpeg-dev libsasl2-dev libncurses5-dev libncursesw5-dev \
libgtk-3-dev libsdl2-dev screen parallel \
htop cpulimit meson autoconf-archive libopus-dev zip unzip sudo

RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.7 /usr/bin/python3
RUN python3 -m pip install install wllvm picire gdown pyyaml

WORKDIR /root

# update llvm toolchains
RUN mkdir llvm-project
RUN cd llvm-project && gdown https://drive.google.com/uc?id=1Qllkb6mdZT1DlzC958ZH_Csc5iuY0N56 && \
tar xf llvm-project-13.tar.gz && cd $OLDPWD
ENV PATH=/root/llvm-project/bin:$PATH

# update binutils
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.35.tar.gz
RUN tar xzvf binutils-2.35.tar.gz; \
cd binutils-2.35; ./configure; make -j8; make install;
RUN rm /usr/bin/objcopy; ln -s /usr/local/bin/objcopy /usr/bin/objcopy

# update gdb
RUN apt-get install -y gdb
RUN wget -q -O ~/.gdbinit-gef.py https://github.com/hugsy/gef/raw/master/gef.py
RUN echo source /root/.gdbinit-gef.py >> ~/.gdbinit
