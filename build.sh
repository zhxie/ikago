export GIT_TAG=$(git describe --abbrev=0 --tags)
export GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
export GIT_COMMIT_COUNT=$(git rev-list --count "$GIT_BRANCH")
export GIT_COMMIT=$(git log --pretty=format:"%h" -1)

go build -ldflags="-X main.version=$GIT_TAG -X main.build=$GIT_COMMIT_COUNT -X main.commit=$GIT_COMMIT" ./cmd/ikago-client
go build -ldflags="-X main.version=$GIT_TAG -X main.build=$GIT_COMMIT_COUNT -X main.commit=$GIT_COMMIT" ./cmd/ikago-server
