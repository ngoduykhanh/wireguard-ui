# Build stage
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.21-alpine3.19 AS builder
LABEL maintainer="Khanh Ngo <k@ndk.name>"

ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG APP_VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

ARG BUILD_DEPENDENCIES="npm \
    yarn"

# Get dependencies
RUN apk add --update --no-cache ${BUILD_DEPENDENCIES}

WORKDIR /build

# Add dependencies
COPY go.mod /build
COPY go.sum /build
COPY package.json /build
COPY yarn.lock /build

# Prepare assets
RUN yarn install --pure-lockfile --production && \
    yarn cache clean

# Move admin-lte dist
RUN mkdir -p assets/dist/js assets/dist/css && \
    cp /build/node_modules/admin-lte/dist/js/adminlte.min.js \
    assets/dist/js/adminlte.min.js && \
    cp /build/node_modules/admin-lte/dist/css/adminlte.min.css \
    assets/dist/css/adminlte.min.css

# Move plugin assets
RUN mkdir -p assets/plugins && \
    cp -r /build/node_modules/admin-lte/plugins/jquery/ \
    /build/node_modules/admin-lte/plugins/fontawesome-free/ \
    /build/node_modules/admin-lte/plugins/bootstrap/ \
    /build/node_modules/admin-lte/plugins/icheck-bootstrap/ \
    /build/node_modules/admin-lte/plugins/toastr/ \
    /build/node_modules/admin-lte/plugins/jquery-validation/ \
    /build/node_modules/admin-lte/plugins/select2/ \
    /build/node_modules/jquery-tags-input/ \
    assets/plugins/

# Add sources
COPY . /build

# Move custom assets
RUN cp -r /build/custom/ assets/

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.appVersion=${APP_VERSION}' -X 'main.buildTime=${BUILD_TIME}' -X 'main.gitCommit=${GIT_COMMIT}'" -a -o wg-ui .

# Release stage
FROM alpine:3.19

RUN addgroup -S wgui && \
    adduser -S -D -G wgui wgui

RUN apk --no-cache add ca-certificates wireguard-tools jq iptables

WORKDIR /app

RUN mkdir -p db

# Copy binary files
COPY --from=builder --chown=wgui:wgui /build/wg-ui .
RUN chmod +x wg-ui
COPY init.sh .
RUN chmod +x init.sh

EXPOSE 5000/tcp
ENTRYPOINT ["./init.sh"]
