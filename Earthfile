VERSION 0.7

build:
  ARG EARTHLY_TARGET_TAG_DOCKER
  ARG tag=$EARTHLY_TARGET_TAG_DOCKER
  BUILD ./cmd/apikey-manager+build --tag $tag

test:
  LOCALLY
  RUN go test -v ./...

ci:
  FROM golang:1.21.1-alpine3.18
  COPY . /work
  WORKDIR /work
  RUN CGO_ENABLED=1 go test -v ./...

release:
  ARG EARTHLY_TARGET_TAG_DOCKER
  ARG repo=jaspeen
  FROM alpine:3.18
  ARG tag=$(echo -n ${EARTHLY_TARGET_TAG_DOCKER} | sed 's/v\(.*\)/\1/')
  BUILD +build --tag $tag --repo $repo
  