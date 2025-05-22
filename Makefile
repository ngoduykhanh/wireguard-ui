.PHONY: serve build
serve: build
	docker run --name wgui -v "$(PWD)/db:/app/db" -it --rm -p5000:5000 wgui -disable-login
build:
	docker build -t wgui .
