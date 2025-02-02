FROM php:8.1-apache

RUN docker-php-ext-install mysqli
RUN a2enmod headers
RUN a2enmod rewrite
RUN sed -i 's/AllowOverride None/AllowOverride All/i' /etc/apache2/apache2.conf

COPY src /var/www/html

EXPOSE 80