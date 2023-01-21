# syntax=docker/dockerfile:1

## Build
FROM golang:1.19 AS build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN go vet -v
RUN go test -v

RUN CGO_ENABLED=0 go build -o /go/bin/app

RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@v2.8.7

RUN nuclei -update-templates -v

## Deploy
FROM gcr.io/distroless/static-debian11

ENV TZ=Asia/Tehran

COPY --from=build /go/bin/app /
COPY --from=build /root/.config /root/.config
COPY --from=build /root/nuclei-templates /root/nuclei-templates

EXPOSE 8080

ENTRYPOINT ["/app"]