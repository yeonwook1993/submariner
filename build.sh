repo=$1
ver=$2

rm package/.image.* bin/linux/amd64/submariner-* || true

make images

for component in submariner-gateway submariner-route-agent submariner-globalnet submariner-networkplugin-syncer
do	
	docker tag quay.io/submariner/${component}:${ver} ${repo}/${component}:${ver}
	docker push ${repo}/${component}:${ver}
done
