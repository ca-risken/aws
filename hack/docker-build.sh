#! /bin/sh
if [ "${IMAGE_TAG}" = "" ]; then
  IMAGE_TAG=latest
fi
if [ "${IMAGE_PREFIX}" = "" ]; then
  IMAGE_PREFIX=default_prefix
fi
cd src/${TARGET} && docker build ${BUILD_OPT} --secret id=GITHUB_USER --secret id=GITHUB_TOKEN -t ${IMAGE_PREFIX}/${TARGET}:${IMAGE_TAG} .
