build-ui:
	./prepare_assets.sh

build:
	CGO_ENABLED=0 go build -v -ldflags="-s -w"

run:
	./wireguard-ui

clean:
	rm -f wireguard-ui
