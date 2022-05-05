FROM php:8.1.4-fpm-alpine
RUN apk --update --no-cache add bash git libwebp zlib-dev libmcrypt-dev libmemcached-dev \
	libpng-dev libwebp-dev libxml2-dev libzip-dev jpeg-dev libjpeg-turbo-dev libxpm-dev \
	freetype-dev libxslt-dev unzip nodejs yarn

RUN docker-php-ext-install pdo_mysql

RUN docker-php-ext-configure gd --enable-gd --with-webp --with-jpeg \
    --with-xpm --with-freetype

RUN docker-php-ext-install gd
RUN docker-php-ext-install soap
RUN docker-php-ext-install xsl

COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN git config --global user.email "sdrean@w3com.fr"
RUN git config --global user.name "sdrean"


# Symfony CLI
#RUN wget https://get.symfony.com/cli/installer -O - | bash && mv /root/.symfony/bin/symfony /usr/local/bin/symfony
WORKDIR /var/www
CMD composer install
CMD yarn
CMD yarn build

CMD php-fpm

EXPOSE 9000

#FROM node:12.16-alpine3.11
#WORKDIR /var/www
#RUN yarn
#RUN yarn run encore production
