FROM witcher/directbasebuild AS directbasebuild
#FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

ARG ARG_PHP_VER=7
ENV PHP_VER=${ARG_PHP_VER}
ENV PHP_INI_DIR="/etc/php/"
ENV LD_LIBRARY_PATH="/wclibs"
ENV PROF_FLAGS="-lcgiwrapper -I/wclibs"
ENV CPATH="/wclibs"

RUN mkdir -p $PHP_INI_DIR/conf.d /phpsrc
COPY repo /phpsrc

COPY witcher-install/php-7.4.33-witcher.patch /phpsrc/witcher.patch
COPY witcher-install/zend_witcher_trace.c witcher-install/zend_witcher_trace.h /phpsrc/Zend/

RUN apt-get update && apt-get install -y apache2 apache2-dev 
# temp for install php-7.4.33
RUN apt-get update && apt-get install -y re2c sqlite3 libsqlite3-dev libonig-dev \
	libcurl4-openssl-dev libpng-dev libzip-dev

RUN cd /phpsrc && git apply witcher.patch && ./buildconf --force

RUN cd /phpsrc &&         \
        ./configure       \
#		--with-config-file-path="$PHP_INI_DIR" \
#		--with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
        --with-apxs2=/usr/bin/apxs \
 		\
		--enable-cgi      \
		--enable-ftp      \
		--enable-mbstring \
		# --enable-zip \
		--with-gd         \
		\
		--with-openssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib       \
		--enable-bcmath \
		--with-curl \
	&& printf "\033[36m[Witcher] PHP $PHP_VER Configure completed \033[0m\n"

#RUN sed -i 's/CFLAGS_CLEAN = /CFLAGS_CLEAN = -L\/wclibs -lcgiwrapper -I\/wclibs /g' /phpsrc/Makefile \
RUN cd /phpsrc \
	&& make clean && make -j $(nproc) \
	&& printf "\033[36m[Witcher] PHP $PHP_VER Make completed \033[0m\n"

RUN cd /phpsrc && make install \
	&& printf "\033[36m[Witcher] PHP $PHP_VER Install completed \033[0m\n" 
	
