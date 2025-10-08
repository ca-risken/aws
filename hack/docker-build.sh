#! /bin/sh
if [ "${IMAGE_TAG}" = "" ]; then
  IMAGE_TAG=latest
fi
if [ "${IMAGE_PREFIX}" = "" ]; then
  IMAGE_PREFIX=default_prefix
fi

# Prepare common package for Docker build
mkdir -p .build/github.com/ca-risken/common/pkg
cp -r ../common/pkg/dlp .build/github.com/ca-risken/common/pkg/

# Create temporary go.mod with modified replace path for Docker
sed 's|replace github.com/ca-risken/common/pkg/dlp => ../common/pkg/dlp|replace github.com/ca-risken/common/pkg/dlp => ./.build/github.com/ca-risken/common/pkg/dlp|' go.mod > go.mod.docker
mv go.mod go.mod.orig
mv go.mod.docker go.mod

# Build Docker image
docker build ${BUILD_OPT} -t ${IMAGE_PREFIX}/${TARGET}:${IMAGE_TAG} -f dockers/${TARGET}/Dockerfile .

# Restore original go.mod
mv go.mod.orig go.mod

# Cleanup
rm -rf .build
