FROM kolobus/komodod:ubuntu
MAINTAINER Mihail Fedorov <mit-license@fedorov.net>

ADD ./ /komodo
ENV HOME /komodo
WORKDIR /komodo

# configure || true or it WILL halt
RUN cd /komodo && \
    ./autogen.sh && \
    ./configure --with-incompatible-bdb --with-gui || true && \
    ./zcutil/build.sh -j4

# Unknown stuff goes here

RUN ln -sf /komodo/src/komodod /usr/bin/komodod && \
    ln -sf /komodo/zcutil/docker-entrypoint.sh /usr/bin/entrypoint && \
    ln -sf /komodo/zcutil/docker-komodo-cli.sh /usr/bin/komodo-cli

CMD ["entrypoint"]
