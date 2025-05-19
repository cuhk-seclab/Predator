
FROM ubuntu:bionic

# Use the fastest APT repo
# COPY --chown=root:root ./files/sources.list.with_mirrors /etc/apt/sources.list
RUN dpkg --add-architecture i386 && apt-get update

ENV DEBIAN_FRONTEND=noninteractive

# Install apt-fast to speed things up
RUN apt-get update \
    && apt-get install -y aria2 curl wget \
    && apt-get install -y git \
    && apt-get install -y python3-apt

#APT-FAST installation
RUN apt-get install -y software-properties-common \
    && add-apt-repository ppa:apt-fast/stable \
    && apt update \
    && apt install apt-fast \
    && apt-fast update --fix-missing \
    && apt-fast -y upgrade

# Install all APT packages
RUN apt-fast install -y sudo software-properties-common net-tools python3-pip \
                        # other stuff
                        mysql-server \
                        # editors
                        vim  \
                        # web
                        apache2 apache2-dev

# Clone base AFL
RUN git clone https://github.com/google/AFL.git /afl

RUN sudo rm -rf /var/lib/mysql \
    && /usr/sbin/mysqld --initialize-insecure

RUN pip3 install --upgrade pip && pip3 install supervisor

# Create wc user and add wc to sudo group
RUN useradd -s /bin/bash -m wc \
    && usermod -aG sudo wc \
    && echo "wc ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

#RUN su - wc -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && mkvirtualenv -p `which python3` witcher"

######### Install phuzzer stuff
RUN apt-fast update && apt-fast install -y libxss1 bison

RUN su - wc -c "pip3 install protobuf==3.19.6 termcolor setuptools"

RUN su - wc -c "pip3 install git+https://github.com/1treeforest/phuzzer"

######### last installs, b/c don't want to wait for phuzzer stuff again.
RUN apt-fast install -y jq \
    && wget https://github.com/sharkdp/bat/releases/download/v0.15.0/bat_0.15.0_amd64.deb -O /root/bat15.deb && sudo dpkg -i /root/bat15.deb


######### wc's environment setup
USER wc
WORKDIR /home/wc
RUN mkdir -p /home/wc/tmp/emacs-saves
RUN git clone -q https://github.com/etrickel/docker_env.git && chown wc:wc -R . && cp -r /home/wc/docker_env/. . && sudo cp -r /home/wc/docker_env/. /root/
COPY config/.bash_prompt /home/wc/.bash_prompt

#RUN echo 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh' >> /home/wc/.bashrc
#RUN echo 'workon witcher' >> /home/wc/.bashrc


######### NodeJS and NPM Setup
RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.39.1/install.sh | bash
RUN echo 'export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh; . $NVM_DIR/bash_completion' >> /home/wc/.bashrc
ENV NVM_DIR=/home/wc/.nvm
RUN . $NVM_DIR/nvm.sh && nvm install 16 && nvm use 16

#RUN sudo mkdir /node_modules && sudo chown wc:wc /node_modules && sudo apt-get install -y npm
RUN sudo apt-get install -y npm libgbm-dev
RUN . $NVM_DIR/nvm.sh && npm install puppeteer cheerio

USER root
RUN mkdir /app && chown www-data:wc /app
COPY --chown=wc:wc /helpers/gremlins.min.js /app


COPY config/supervisord.conf /etc/supervisord.conf
RUN if [ ! -d /run/sshd ]; then mkdir /run/sshd; chmod 0755 /run/sshd; fi
RUN mkdir /var/run/mysqld; chown mysql:mysql /var/run/mysqld
# mysql configuration for disk access, used when running 25+ containers on single system
RUN printf "[mysqld]\ninnodb_use_native_aio = 0\n" >> /etc/mysql/my.cnf

RUN ln -s /p /projects

COPY config/network_config.sh /netconf.sh
RUN chmod +x /netconf.sh

ENV TZ=Asia/Hong_Kong
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \ 
    && echo "export TZ=$TZ" >> /home/wc/.bashrc \
    && usermod -a -G www-data wc

#"Installing" the Witcher's Dash that abends on a parsing error when STRICT=1 is set.
#

#COPY --from=hacrs/build-httpreqr /Witcher/base/httpreqr/httpreqr /httpreqr
COPY --from=witcher/directbasebuild /httpreqr/httpreqr.64 /httpreqr

COPY afl /afl
ENV AFL_PATH=/afl

# Install AFL
RUN cd /afl \
    && make && make install

COPY --chown=wc:wc helpers/ /helpers/
COPY --chown=wc:wc phuzzer /helpers/phuzzer
COPY --chown=wc:wc witcher /witcher/

RUN . $NVM_DIR/nvm.sh && cd /helpers/request_crawler && npm install
RUN su - wc -c "pip3 install nclib==1.0.2 archr ipdb ply &&  cd /helpers/phuzzer && pip3 install -e . &&  cd /witcher && pip3 install -e ."

COPY --from=witcher/directbasebuild /wclibs/lib_db_fault_escalator.so /lib/
RUN mkdir -p /wclibs && ln -s /lib/lib_db_fault_escalator.so /wclibs/ && ln -s /lib/lib_db_fault_escalator.so /wclibs/libcgiwrapper.so && ln -s /lib/lib_db_fault_escalator.so /lib/libcgiwrapper.so

# copy x86_64 version of dash
COPY --from=witcher/directbasebuild /Widash/archbuilds/dash /crashing_dash

#COPY --chown=wc:wc bins /bins

ENV CONTAINER_NAME="witcher"
ENV WC_TEST_VER="EXWICHR"
ENV WC_FIRST=""
ENV WC_CORES="10"
ENV WC_TIMEOUT="1200"
ENV WC_SET_AFFINITY="0"
# single script takes "--target scriptname"
ENV WC_SINGLE_SCRIPT=""

RUN mkdir -p /test && chown wc:wc /test

RUN ln -s /usr/local/bin/supervisord /usr/bin/supervisord && ln -s /usr/local/bin/pidproxy /usr/bin/pidproxy

CMD ["/bin/sh", "-c", "/netconf.sh && exec /usr/bin/supervisord -c /etc/supervisord.conf"]



