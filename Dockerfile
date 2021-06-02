# Build stage
FROM golang:1.14.2-alpine3.11 as builder
LABEL maintainer="Khanh Ngo <k@ndk.name"
ARG BUILD_DEPENDENCIES="npm \
    yarn"

# Get dependencies
RUN apk add --update --no-cache ${BUILD_DEPENDENCIES}
ENV USER=admin PASS=admin
WORKDIR /build

# Add sources
COPY . /build

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

# Move custom assets
RUN cp -r /build/custom/ assets/

# Get go modules and build tool
RUN go mod download && \
    go get github.com/GeertJohan/go.rice/rice

# Build
RUN rice embed-go && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o wg-ui .

# Release stage
FROM alpine:3.11

RUN addgroup -S wgui && \
    adduser -S -D -G wgui wgui

RUN apk --no-cache add ca-certificates

WORKDIR /app

RUN mkdir -p db

# Copy binary files
COPY --from=builder --chown=wgui:wgui /build/wg-ui /app

RUN chmod +x wg-ui

EXPOSE 5000/tcp
HEALTHCHECK CMD ["wget","--output-document=-","--quiet","--tries=1","http://127.0.0.1:5000/login"]
ENTRYPOINT ["./wg-ui"]
