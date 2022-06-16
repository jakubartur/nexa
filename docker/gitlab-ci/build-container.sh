set -e
docker build --no-cache -t bchunlimited/nexa:ubuntu20.04 .
docker push bchunlimited/nexa:ubuntu20.04
