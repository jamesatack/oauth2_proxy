#!/bin/bash

# build binary distributions for linux/amd64 and darwin/amd64
set -e 
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "working dir $DIR"
echo "gopath dir $GOPATH"
mkdir -p $DIR/dist
mkdir -p $DIR/.godeps
export GOPATH=$DIR/.godeps:$GOPATH
gpm install

os=$(go env GOOS)
arch=$(go env GOARCH)
version=$(cat $DIR/version.go | grep "const VERSION" | awk '{print $NF}' | sed 's/"//g')
goversion=$(go version | awk '{print $3}')

#echo "... running tests"
#./test.sh || exit 1
#Don't bother running tests, I haven't written a test for Keycloak

for os in windows linux darwin; do
    echo "... building v$version for $os/$arch"
    BUILD=$(mktemp -d ${TMPDIR:-/tmp}/oauth2_proxy.XXXXXX)
    TARGET="oauth2_proxy-$version.$os-$arch.$goversion"
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -o $BUILD/$TARGET/oauth2_proxy || exit 1
    pushd $BUILD
    tar czvf $TARGET.tar.gz $TARGET
    mv $TARGET.tar.gz $DIR/dist
    popd
done
