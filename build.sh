export GIT_TAG=$(git describe --abbrev=0 --tags)
export GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
export GIT_COMMIT_COUNT=$(git rev-list --count "$GIT_BRANCH")
export GIT_COMMIT=$(git log --pretty=format:"%h" -1)




if [[ $1 == "arm64" ]]
then
    env CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV" go build -ldflags="-X main.version=$GIT_TAG -X main.build=$GIT_COMMIT_COUNT -X main.commit=$GIT_COMMIT"  -o ikago-client-arm64 ./cmd/ikago-client
    env CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV" go build -ldflags="-X main.version=$GIT_TAG -X main.build=$GIT_COMMIT_COUNT -X main.commit=$GIT_COMMIT"  -o ikago-server-arm64 ./cmd/ikago-server
else
    go build -ldflags="-X main.version=$GIT_TAG -X main.build=$GIT_COMMIT_COUNT -X main.commit=$GIT_COMMIT" ./cmd/ikago-client
    go build -ldflags="-X main.version=$GIT_TAG -X main.build=$GIT_COMMIT_COUNT -X main.commit=$GIT_COMMIT" ./cmd/ikago-server
fi


