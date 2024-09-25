#!/bin/sh
# If GO_VERSION is not set, use DEFAULT_GO_VERSION
DEFAULT_GO_VERSION=1.21.3
INSTALL_GO_VERSION=${GO_VERSION:-$DEFAULT_GO_VERSION}

if [[ "${ARCH}" = "" ]]; then
  echo "environment value ARCH is not set"
  exit 1
fi


if [[ "${ARCH}" = "arm64" ]]; then
  curl -OL "https://go.dev/dl/go${INSTALL_GO_VERSION}.linux-arm64.tar.gz"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "go${INSTALL_GO_VERSION}.linux-arm64.tar.gz"
else
  goenv install ${INSTALL_GO_VERSION}
  goenv global ${INSTALL_GO_VERSION}
fi
