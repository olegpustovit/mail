FROM node:22-alpine AS frontend
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm test && npm run build

FROM golang:1.26.11-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
# The Microapps ID client lives in a private repository: build with --secret id=github_token,src=<file>.
RUN apk add --no-cache git
RUN --mount=type=secret,id=github_token \
    GOPRIVATE=github.com/olegpustovit/identity \
    sh -c 'git config --global url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf https://github.com/; go mod download; status=$?; rm -f /root/.gitconfig; exit $status'
COPY . .
COPY --from=frontend /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /mail-server ./cmd/mail

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mail-server /mail-server
ENV MAIL_ADDR=0.0.0.0:4290
EXPOSE 4290
USER nonroot:nonroot
ENTRYPOINT ["/mail-server"]
