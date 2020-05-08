$GIT_TAG=git describe --abbrev=0 --tags
$GIT_BRANCH=git rev-parse --abbrev-ref HEAD
$GIT_COMMIT_COUNT=git rev-list --count ${GIT_BRANCH}
$GIT_COMMIT=git log --pretty=format:"%h" -1

goversioninfo -o .\cmd\ikago-client\main.syso .\build\versioninfo.json
go build -ldflags="-X main.version=${GIT_TAG} -X main.build=${GIT_COMMIT_COUNT} -X main.commit=${GIT_COMMIT}" ./cmd/ikago-client
go build -ldflags="-X main.version=${GIT_TAG} -X main.build=${GIT_COMMIT_COUNT} -X main.commit=${GIT_COMMIT}" ./cmd/ikago-server
