$GIT_TAG=git describe --abbrev=0 --tags
$GIT_BRANCH=git rev-parse --abbrev-ref HEAD
$GIT_COMMIT_COUNT=git rev-list --count ${GIT_BRANCH}
$GIT_COMMIT=git log --pretty=format:"%h" -1

$VERS=$GIT_TAG.replace("v", "").Split(".")
$VER_MAIN=$VERS[0] -as [int]
$VER_SUB=$VERS[1] -as [int]
$VER_PATCH=$VERS[2] -as [int]

$PROD_VER="$($GIT_TAG)-$($GIT_COMMIT_COUNT) ($($GIT_COMMIT))"

goversioninfo -product-version ${PROD_VER} -ver-major ${VER_MAIN} -ver-minor ${VER_SUB} -ver-patch ${VER_PATCH} -ver-build ${GIT_COMMIT_COUNT} -o .\cmd\ikago-client\main.syso .\build\windows\IkaGo-client.json
go build -ldflags="-X main.version=${GIT_TAG} -X main.build=${GIT_COMMIT_COUNT} -X main.commit=${GIT_COMMIT}" .\cmd\ikago-client
go build -ldflags="-X main.version=${GIT_TAG} -X main.build=${GIT_COMMIT_COUNT} -X main.commit=${GIT_COMMIT}" .\cmd\ikago-server
