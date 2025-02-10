FROM php:8.1-apache

RUN apt-get update && apt-get install -y \
    libicu-dev \
    libssl-dev \
    libc-client-dev \
    libkrb5-dev \
    && docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
    && docker-php-ext-install imap mysqli \
    && a2enmod headers rewrite \
    && sed -i 's/AllowOverride None/AllowOverride All/i' /etc/apache2/apache2.conf \
    && rm -rf /var/lib/apt/lists/*

COPY src /var/www/html

EXPOSE 80