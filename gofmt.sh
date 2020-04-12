#!/bin/sh

if [ x"$1" = x'-u' ]
then
	go get -u golang.org/x/tools/cmd/goimports
	echo "Updated." >&2
	exit
fi

export GOPATH=`go env GOPATH`:`pwd`

if [ x"$1" = x"-all" ]
then
	exec goimports -local 'gokidban/' -w src/gokidban
fi

if [ "$#" -lt 1 ]
then
	printf "Usage:\n\t%s a.go ...\n\t%s -all\n\t%s -u\n" "$0" "$0" "$0" >&2
	exit 1
fi

exec goimports -local 'gokidban/' -w "$@"
