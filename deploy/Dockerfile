# Build from the repository root: docker build -f deploy/Dockerfile -t kalitka .
#
# Both engines are pinned, because AmneziaWG generations do not interoperate and an
# unplanned upgrade could cut off a gateway nobody can reach.

FROM golang:1.25.12 AS amneziawg-go
ARG AMNEZIAWG_GO_REF=v3.1.20260828
RUN git clone --depth 1 --branch "${AMNEZIAWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go.git /src
WORKDIR /src
RUN go mod verify && go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -o /out/amneziawg-go

FROM alpine:3.22 AS amneziawg-tools
ARG AMNEZIAWG_TOOLS_REF=v3.1.20260812
RUN apk add --no-cache git build-base linux-headers && \
    git clone --depth 1 --branch "${AMNEZIAWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools.git /src && \
    make -C /src/src

FROM golang:1.25.12 AS kalitka
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/kalitka ./cmd/kalitka

FROM alpine:3.22
RUN apk add --no-cache bash iproute2 iptables
COPY --from=amneziawg-go /out/amneziawg-go /usr/bin/amneziawg-go
COPY --from=amneziawg-tools /src/src/wg /usr/bin/awg
COPY --from=amneziawg-tools /src/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=kalitka /out/kalitka /usr/bin/kalitka
RUN chmod +x /usr/bin/awg /usr/bin/awg-quick
ENV KALITKA_STATE=/var/lib/kalitka
VOLUME /var/lib/kalitka
ENTRYPOINT ["kalitka"]
