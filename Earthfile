VERSION 0.7

build:
  ARG EARTHLY_TARGET_TAG_DOCKER
  ARG repo=jaspeen
  ARG tag=$EARTHLY_TARGET_TAG_DOCKER
  FROM DOCKERFILE -f ./Dockerfile ./
  SAVE IMAGE --push $repo/apikeyman:$tag

test:
  LOCALLY
  RUN go test -v ./...

ci:
  FROM golang:1.21.1-alpine3.18
  COPY . /work
  WORKDIR /work
  # TODO: here we need dind to run postgres
  RUN go test -short -v ./...

release:
  ARG EARTHLY_TARGET_TAG_DOCKER
  ARG repo=jaspeen
  FROM alpine:3.18
  ARG tag=$(echo -n ${EARTHLY_TARGET_TAG_DOCKER} | sed 's/v\(.*\)/\1/')
  BUILD +build --tag $tag --repo $repo
  