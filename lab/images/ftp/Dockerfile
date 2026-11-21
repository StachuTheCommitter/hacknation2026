FROM alpine:3.20
RUN apk add --no-cache vsftpd && mkdir -p /var/run/vsftpd/empty && \
    printf 'listen=YES\nanonymous_enable=NO\nlocal_enable=NO\nseccomp_sandbox=NO\nftpd_banner=Wydzialowy serwer FTP\nbackground=NO\n' > /etc/vsftpd/vsftpd.conf
EXPOSE 21
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
