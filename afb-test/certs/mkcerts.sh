#!/bin/sh
#-----------------------------
START=`pwd`

if test $# -eq 1; then
  mkdir -p $1
  cd $1
  DST=`pwd`
else
  DST=.
fi

BASE=$START/$(dirname $0)
cd $BASE
#-----------------------------

#-----------------------------
make_root_certificate() {
	local name=${1:-root}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                --outder \
		--outfile=$DST/_$name.key.der
	certtool \
		--generate-self-signed \
		--template=templ-root.cfg \
		--load-privkey=$DST/_$name.key.der \
		--no-text \
                --inder \
                --outder \
		--outfile=$DST/_$name.der
}
#-----------------------------
make_sub_certificate() {
	local name=${1:-sub} auth=${2:-root}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                --outder \
		--outfile=$DST/_$name.key.der
	certtool \
		--generate-certificate \
		--template=templ-sub.cfg \
		--load-privkey=$DST/_$name.key.der \
		--load-ca-privkey=$DST/_$auth.key.der \
		--load-ca-certificate=$DST/_$auth.der \
		--no-text \
                --inder \
                --outder \
		--outfile=$DST/_$name.der
	cat _$name.der _$auth.der > _$name.list.der
}
#-----------------------------
make_end_certificate() {
	local name=${1:-end} auth=${2:-sub}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                --outder \
		--outfile=$DST/_$name.key.der
	certtool \
		--generate-certificate \
		--template=templ-end.cfg \
		--load-privkey=$DST/_$name.key.der \
		--load-ca-privkey=$DST/_$auth.key.der \
		--load-ca-certificate=$DST/_$auth.der \
		--no-text \
                --inder \
                --outder \
		--outfile=$DST/_$name.der
	cat _$name.der _$auth.list.der > _$name.list.der
}
#-----------------------------
make_root_certificate root
make_sub_certificate  sub
make_end_certificate  end

make_root_certificate root2
make_sub_certificate  sub2 root2
make_end_certificate  end2 sub2
