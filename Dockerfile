FROM golang:1.16-alpine
WORKDIR /go/src/github.com/envato/ejsonkms
COPY . .
RUN apk add git gcc musl-dev
RUN go get
