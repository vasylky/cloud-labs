FROM alpine:3.18
RUN apk add --no-cache curl bash
WORKDIR /app
COPY loadgen.sh /app/loadgen.sh
RUN chmod +x /app/loadgen.sh
ENTRYPOINT ["/app/loadgen.sh"]
