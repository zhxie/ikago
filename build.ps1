$GIT_TAG=git describe --abbrev=0 --tags
$GIT_COMMIT=git log --pretty=format:"%h" -1

go build -ldflags="-X main.version=${GIT_TAG} -X main.build=${GIT_COMMIT}" ./cmd/ikago-client
go build -ldflags="-X main.version=${GIT_TAG} -X main.build=${GIT_COMMIT}" ./cmd/ikago-server
