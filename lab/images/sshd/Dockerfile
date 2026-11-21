# Prawdziwy OpenSSH; wersja zależy od wydania Alpine (3.18 → OpenSSH 9.3, 3.20 → 9.7) – zmiana w kroku 2 scenariusza.
ARG ALPINE=3.18
FROM alpine:${ALPINE}
RUN apk add --no-cache openssh && ssh-keygen -A && echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
