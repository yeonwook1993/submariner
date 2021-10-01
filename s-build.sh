rm package/.image.* bin/linux/amd64/submariner-* || true

make images

for component in submariner-gateway submariner-route-agent submariner-globalnet submariner-networkplugin-syncer
do	
	docker tag quay.io/submariner/${component}:devel yeonwook1993/${component}:devel
	docker tag quay.io/submariner/${component}:devel
	docker push yeonwook1993/${component}:devel
done

chown -R classact /home/classact/vpp_wireguard/submariner
