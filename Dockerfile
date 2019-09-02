FROM golang:1.12-alpine
ENV GO111MODULE=on
WORKDIR /go/src/github.com/envato/ejsonkms
COPY . .
RUN apk add git gcc musl-dev
RUN go get
