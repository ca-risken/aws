#!/bin/bash -e

cd "$(dirname "$0")"

# load env
. ../env.sh

# setting remote repository
TAG="local-test-$(date '+%Y%m%d')"
IMAGE_AWS="aws/aws"
IMAGE_GUARDDUTY="aws/guardduty"
IMAGE_ACCESSANALYZER="aws/accessanalyzer"
IMAGE_ADMINCHECKER="aws/adminchecker"
IMAGE_CLOUDSPLOIT="aws/cloudsploit"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
REGISTORY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# build & push
aws ecr get-login-password --region ${AWS_REGION} \
  | docker login \
    --username AWS \
    --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_AWS}:${TAG} ../src/aws/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_GUARDDUTY}:${TAG} ../src/guard-duty/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_ACCESSANALYZER}:${TAG} ../src/access-analyzer/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_ADMINCHECKER}:${TAG} ../src/admin-checker/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_CLOUDSPLOIT}:${TAG} ../src/cloudsploit/

docker tag ${IMAGE_AWS}:${TAG}            ${REGISTORY}/${IMAGE_AWS}:${TAG}
docker tag ${IMAGE_GUARDDUTY}:${TAG}      ${REGISTORY}/${IMAGE_GUARDDUTY}:${TAG}
docker tag ${IMAGE_ACCESSANALYZER}:${TAG} ${REGISTORY}/${IMAGE_ACCESSANALYZER}:${TAG}
docker tag ${IMAGE_ADMINCHECKER}:${TAG}   ${REGISTORY}/${IMAGE_ADMINCHECKER}:${TAG}
docker tag ${IMAGE_CLOUDSPLOIT}:${TAG}    ${REGISTORY}/${IMAGE_CLOUDSPLOIT}:${TAG}

docker push ${REGISTORY}/${IMAGE_AWS}:${TAG}
docker push ${REGISTORY}/${IMAGE_GUARDDUTY}:${TAG}
docker push ${REGISTORY}/${IMAGE_ACCESSANALYZER}:${TAG}
docker push ${REGISTORY}/${IMAGE_ADMINCHECKER}:${TAG}
docker push ${REGISTORY}/${IMAGE_CLOUDSPLOIT}:${TAG}
