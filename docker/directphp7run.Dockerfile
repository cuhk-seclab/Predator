##################################################################################################################################
FROM witcher/directbaserun AS directphp7run
##################################################################################################################################

COPY --from=witcher/directphp7build /usr/local/bin/php /usr/local/bin/php-config /usr/local/bin/phpize /usr/local/bin/php-cgi /usr/local/bin/phar.phar /usr/local/bin/phpdbg /usr/local/bin/
COPY --from=witcher/directphp7build /usr/local/lib/php/build/ /usr/local/lib/php/build/
COPY --from=witcher/directphp7build /usr/lib/apache2/modules/libphp7.so /usr/lib/apache2/modules/libphp7.so
COPY --from=witcher/directphp7build /usr/local/include/php/ /usr/local/include/php/
COPY --from=witcher/directphp7build /usr/local/bin/ /usr/local/bin/
# for zip curl gd ... extensions
COPY --from=witcher/directphp7build /phpsrc/ext /phpext

######### apache, php, and crawler setup
RUN apt-fast install -y libpng16-16 net-tools ca-certificates fonts-liberation libappindicator3-1 libasound2 \
                        libatk-bridge2.0-0 libatk1.0-0  libc6 libcairo2 libcups2 libdbus-1-3  libexpat1 libfontconfig1 \
                        libgbm1 libgcc1 libglib2.0-0 libgtk-3-0  libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 \
                        libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 \
                        libxi6 libxrandr2 libxrender1 libxss1 libxtst6 lsb-release wget xdg-utils \
                        unzip graphviz libgraphviz-dev chromium-chromedriver sqlite \
                        libcurl4-openssl-dev libpng-dev libzip-dev pkg-config libicu-dev \
                        php-xdebug 
                        # php-opcache

RUN php -i

ENV APACHE_RUN_DIR=/etc/apache2/

# + temp add
COPY etc/apache2.conf /etc/apache2/apache2.conf

RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
# RUN ln -s /etc/php/7.1/mods-available/mcrypt.ini /etc/php/7.3/mods-available/ && phpenmod mcrypt

RUN sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf \
  && sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf

# change apache to forking instead of thread
RUN rm -f /etc/apache2/mods-enabled/mpm_event.* \
    && rm -f /etc/apache2/mods-enabled/mpm_prefork.* \
    && ln -s /etc/apache2/mods-available/mpm_prefork.load /etc/apache2/mods-enabled/mpm_prefork.load \
    && ln -s /etc/apache2/mods-available/mpm_prefork.conf /etc/apache2/mods-enabled/mpm_prefork.conf

COPY config/supervisord.conf /etc/supervisord.conf
COPY config/php.ini /usr/local/lib/php.ini
COPY config/php.ini /etc/php/7.2/apache2/php.ini
COPY config/php7.conf config/php7.load /etc/apache2/mods-available/

RUN ln -s /etc/apache2/mods-available/php7.load /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/php7.conf /etc/apache2/mods-enabled/ && rm /usr/bin/php && ln -s /usr/local/bin/php /usr/bin/php

RUN a2enmod rewrite
ENV PHP_UPLOAD_MAX_FILESIZE=10M
ENV PHP_POST_MAX_SIZE=10M
RUN rm -fr /var/www/html && ln -s /app /var/www/html

#### XDEBUG #+ temp disable
RUN cd /phpext/xdebug && phpize && ./configure --enable-xdebug && make -j $(nproc) && make install

#### for ZIP gd curl extension
RUN cd /phpext/zip && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/gd && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/curl && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/intl && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install

COPY --chown=wc:wc  config/phpinfo_test.php config/db_test.php config/cmd_test.php config/run_segfault_test.sh /app/

# disable directory browsing in apache2
RUN sed -i 's/Indexes//g' /etc/apache2/apache2.conf && \
    echo "DirectoryIndex index.php index.phtml index.html index.htm" >> /etc/apache2/apache2.conf

# add index
COPY config/000-default.conf /etc/apache2/sites-available/

#+ zip curl gd +
RUN printf '\nextension=zip\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  # && printf '\nextension=curl\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  && printf '\nextension=gd\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  && printf '\nextension=intl\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) 

RUN echo 'alias p="python -m witcher --affinity $(( $(ifconfig |egrep -oh "inet 172[\.0-9]+"|cut -d "." -f4) * 2 ))"' >> /home/wc/.bashrc
COPY config/py_aff.alias /root/py_aff.alias
RUN cat /root/py_aff.alias >> /home/wc/.bashrc

# RUN cp /bin/dash /bin/saved_dash && cp /crashing_dash /bin/dash
RUN cp /usr/bin/python3 /usr/bin/python
# there's a problem with building xdebug and the modifid dash, so copy after xdebug
COPY --from=witcher/directbasebuild /Widash/archbuilds/dash /bin/dash

COPY --chown=wc:wc  config/codecov_conversion.py config/enable_cc.php /
# Enable sanbox
RUN sysctl -w kernel.unprivileged_userns_clone=1

RUN cd /tmp && update-alternatives --install /usr/bin/php php /usr/local/bin/php 100 \
  && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
  && php composer-setup.php && mv composer.phar /usr/local/bin/composer

CMD ["/bin/sh", "-c", "/usr/bin/supervisord -c /etc/supervisord.conf"]

# # Install bWAPP
RUN cd / && git clone https://github.com/1TreeForest/bWAPP.git \
  && mv /bWAPP/* /var/www/html
# curl http://localhost/bWAPP/install.php?install=yes > /dev/null 2>&1
