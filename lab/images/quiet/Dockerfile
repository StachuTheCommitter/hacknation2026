# Host bez otwartych portów (odpowiada RST / ICMP) albo – z DROP=1 – odrzucający wszystko (wymaga NET_ADMIN).
FROM alpine:3.20
RUN apk add --no-cache iptables
CMD ["sh", "-c", "if [ \"$DROP\" = 1 ]; then iptables -P INPUT DROP; fi; exec sleep infinity"]
