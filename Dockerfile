# Stage 1: Runtime
FROM alpine:3.19

# Install only what Podump needs
RUN apk add --no-cache tcpdump ca-certificates

# Best practice: tcpdump needs specific capabilities, 
# but we will run as root since it's an ephemeral sniffer
ENTRYPOINT ["tcpdump"]
