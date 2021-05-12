.ONESHELL:

DATE = $(shell date +'%s')

docker-build:
	docker build --build-arg always_upgrade="$(DATE)" -t cypherhat/pillbox:latest .

run:
	docker-compose -f docker/docker-compose.yml up --build --remove-orphans

all: docker-build run