FROM alpine:3.21.3

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories \
  && apk add --update --no-cache openssh-client autossh

ENTRYPOINT ["autossh", "-M", "0"]
CMD ["--help"]
