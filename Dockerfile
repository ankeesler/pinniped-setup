FROM golang:1.16.6 as builder

WORKDIR /workspace
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o pinniped-setup .

FROM debian:bullseye-slim
WORKDIR /
COPY --from=builder /workspace/pinniped-setup .
ENTRYPOINT ["/pinniped-setup"]
