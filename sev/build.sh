#!/bin/bash

SCRIPT_DIR="$(dirname $0)"
. ${SCRIPT_DIR}/common.sh
[ -e /etc/os-release ] && . /etc/os-release

function usage()
{
	echo "Usage: $0 [OPTIONS] [COMPONENT]"
	echo "  where COMPONENT is an individual component to build:"
	echo "    qemu, ovmf, kernel [host|guest]"
	echo "    (default is to build all components)"
	echo "  where OPTIONS are:"
	echo "  --install PATH          Installation path (default $INSTALL_DIR)"
	echo "  --package               Create a tarball containing built components"
	echo "  -h|--help               Usage information"

	exit 1
}

INSTALL_DIR="`pwd`/local-installation/usr/local"

while [ -n "$1" ]; do
	case "$1" in
	--install)
		[ -z "$2" ] && usage
		INSTALL_DIR="$2"
		shift; shift
		;;
	-h|--help)
		usage
		;;
	--package)
		BUILD_PACKAGE="1"
		shift
		;;
	-*|--*)
		echo "Unsupported option: [$1]"
		usage
		;;
	*)
		break
		;;
	esac
done

mkdir -p $INSTALL_DIR
IDIR=$INSTALL_DIR
INSTALL_DIR=$(readlink -e $INSTALL_DIR)
[ -n "$INSTALL_DIR" -a -d "$INSTALL_DIR" ] || {
	echo "Installation directory [$IDIR] does not exist, exiting"
	exit 1
}

if [ -z "$1" ]; then
	build_install_qemu "$INSTALL_DIR"
	build_install_ovmf "$INSTALL_DIR/share/qemu"
else
	case "$1" in
	qemu)
		build_install_qemu "$INSTALL_DIR"
		;;
	ovmf)
		build_install_ovmf "$INSTALL_DIR/share/qemu"
		;;
	esac
fi

if [[ "$BUILD_PACKAGE" = "1" ]]; then
	OUTPUT_DIR="snp-release-`date "+%F"`"
	rm -rf $OUTPUT_DIR
	mkdir -p $OUTPUT_DIR/usr
	cp -dpR $INSTALL_DIR $OUTPUT_DIR/usr/

	cp launch-qemu.sh ${OUTPUT_DIR} -v
	cp install.sh ${OUTPUT_DIR} -v
	cp kvm.conf ${OUTPUT_DIR} -v
	tar zcvf ${OUTPUT_DIR}.tar.gz ${OUTPUT_DIR}
fi
