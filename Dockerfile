ARG GO_VERSION=1.17

FROM golang:${GO_VERSION}-alpine as build

RUN apk --no-cache add make ca-certificates 
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src/
RUN make build
ENTRYPOINT [ "/src/bin/horismos" ]

FROM debian:buster
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=build /src/bin/horismos /bin/horismos
ENTRYPOINT [ "/bin/horismos" ]