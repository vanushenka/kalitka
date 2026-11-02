# The image of the end-to-end test. Build from the repository root:
#   docker build -f test/trunk/Dockerfile -t kalitka:test .
#
# Besides kalitka it holds the upstream awg tool, so that the test checks the engine's
# real settings with something other than our own code. The tool is pinned to a tag and
# its commit: a tag that has moved fails the build.

FROM alpine:3.22 AS amneziawg-tools
ARG AMNEZIAWG_TOOLS_REF=v3.1.20260812
ARG AMNEZIAWG_TOOLS_COMMIT=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
RUN apk add --no-cache git build-base linux-headers && \
    git clone --depth 1 --branch "${AMNEZIAWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools.git /src && \
    test "$(git -C /src rev-parse HEAD)" = "${AMNEZIAWG_TOOLS_COMMIT}" && \
    make -C /src/src

FROM golang:1.25.12 AS kalitka
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/kalitka ./cmd/kalitka

FROM alpine:3.22
# iptables is for the container that plays the NAT.
RUN apk add --no-cache iproute2 iptables
COPY --from=amneziawg-tools /src/src/wg /usr/bin/awg
COPY --from=kalitka /out/kalitka /usr/bin/kalitka
RUN chmod +x /usr/bin/awg
ENV KALITKA_STATE=/var/lib/kalitka
VOLUME /var/lib/kalitka
ENTRYPOINT ["kalitka"]
