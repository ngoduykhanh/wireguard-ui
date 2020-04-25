# Build stage
FROM golang:1.14.2-alpine3.11 as builder
LABEL maintainer="Khanh Ngo <k@ndk.name"
ARG BUILD_DEPENDENCIES="npm \
    yarn"

# Get dependencies
RUN apk add --update --no-cache ${BUILD_DEPENDENCIES}

WORKDIR /build

# Add sources
COPY . /build

# Get application dependencies and build
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o wg-ui .

# Prepare assets
RUN yarn install --pure-lockfile --production && \
    yarn cache clean

# Move plugin assets
RUN mkdir -p /assets/plugins && \
    cp -r /build/node_modules/admin-lte/plugins/jquery/ \
    /build/node_modules/admin-lte/plugins/fontawesome-free/ \
    /build/node_modules/admin-lte/plugins/bootstrap/ \
    /build/node_modules/admin-lte/plugins/icheck-bootstrap/ \
    /build/node_modules/admin-lte/plugins/toastr/ \
    /build/node_modules/admin-lte/plugins/jquery-validation/ \
    /build/node_modules/admin-lte/plugins/select2/ \
    /build/node_modules/jquery-tags-input/ \
    /assets/plugins/


# Release stage
FROM alpine3.11

RUN addgroup -S wgui && \
    adduser -S -D -G wgui wgui

RUN apk --no-cache add ca-certificates

WORKDIR /app

RUN mkdir -p db

# Copy binary files
COPY --from=builder --chown=wgui:wgui /build/wg-ui /app
# Copy templates
COPY --from=builder --chown=wgui:wgui /build/templates /app/templates
# Copy assets
COPY --from=builder --chown=wgui:wgui /build/node_modules/admin-lte/dist/js/adminlte.min.js /app/assets/dist/js/adminlte.min.js
COPY --from=builder --chown=wgui:wgui /build/node_modules/admin-lte/dist/css/adminlte.min.css /app/assets/dist/css/adminlte.min.css
COPY --from=builder --chown=wgui:wgui /assets/plugins /app/assets/plugins

RUN chmod +x wg-ui

EXPOSE 5000/tcp
HEALTHCHECK CMD ["wget","--output-document=-","--quiet","--tries=1","http://127.0.0.1:5000/"]
ENTRYPOINT ["./wg-ui"]
