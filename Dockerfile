FROM ubuntu:14.04
MAINTAINER Maciej Pasternacki <maciej@ginzametrics.com>

RUN apt-get update && apt-get install --yes build-essential libperl-dev cpanminus ca-certificates libssl-dev libexpat1-dev && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
ADD . /srv/App-OdinAuthorizer
RUN chgrp www-data /srv/App-OdinAuthorizer/environments && chmod g+w /srv/App-OdinAuthorizer/environments && cd /srv/App-OdinAuthorizer && rm -rf .git && cpanm --installdeps --notest . && cpanm --notest Starman Template::Plugin::EnvHash
WORKDIR /srv/App-OdinAuthorizer

USER www-data
EXPOSE 5001
CMD ["/srv/App-OdinAuthorizer/run"]
