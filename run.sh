#!/bin/sh -x

if [ $(id -u) -ne 0 ]; then
    exec sudo -E "$0" "$@"
fi

base=$(dirname $0)

APP="$base/build-root/install-vpp_debug-native/vpp/bin/vpp"
ARGS="-c $base/startup_debug.conf"

USAGE="Usage: run.sh [-r] [ debug ]
       debug:	executes vpp under gdb"

while getopts ":r" opt; do
    case $opt in
	r)
	    APP="$base/build-root/install-vpp-native/vpp/bin/vpp"
	    ARGS="-c $base/startup.conf"
	    ;;
	\?)
	    echo "Invalid option: -$OPTARG\n" >&2
	    echo "$USAGE" >&2
	    exit 1
	    ;;
    esac
done
shift $((OPTIND-1))

if test -z "$1"; then
    $APP $ARGS
elif test "$1" = "debug"; then
    shift
    gdb -ex 'set print pretty on' -ex 'run' --args $APP $ARGS $@
else
    echo "$USAGE" >&2
    exit 1
fi
