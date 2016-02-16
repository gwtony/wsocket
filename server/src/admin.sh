#!/bin/bash

if [ $# -lt 3 ]; then
	echo -e "Usage: $0 host port cmd [arg]\n"
	echo -e "Support cmd:"
	echo -e "    'list'   : list all l7server name, no arg"
	echo -e "    'reload' : reload a l7server, arg is the l7server name"
	echo -e "Example:"
	echo -e "    $0 127.0.0.1 8003 list"
	echo -e "    $0 127.0.0.1 8003 reload l7_one"
	exit
fi

host=$1
port=$2
cmd=$3
arg=$4

if [ ! $host -o ! $port ]; then
	echo "Error: address not valid"
	exit
fi


case $cmd in
	"reload")
		if [ ! $arg ]; then
			echo "Error: no arg"
		else 
			echo "reload $arg" | nc $host $port
		fi
	;;
	"list")
		echo "list" | nc $host $port
	;;
	*)
		echo "Error: unknown command"
	;;
esac

