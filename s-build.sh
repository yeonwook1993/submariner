set -e
rm package/.image.submariner-gateway bin/linux/amd64/submariner-gateway || true

make  bin/linux/amd64/submariner-gateway package/.image.submariner-gateway

docker tag quay.io/submariner/submariner-gateway:devel yeonwook1993/submariner-gateway:devel
docker push yeonwook1993/submariner-gateway:devel
