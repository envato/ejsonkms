FROM golang:1.24-alpine
WORKDIR /go/src/github.com/envato/ejsonkms
COPY . .
RUN apk add git gcc musl-dev
RUN go get
