#!/bin/sh

U0=0
U1=0
ERR=0

while read LINE; do
	N=`echo $LINE | cut -f3 -d' '`
	if [ $N -eq 1278 ] ; then
#	if [ $N -eq 10376 ] ; then
		U0=$((U0+1))
	elif [ $N -eq 140 ] ; then
		U1=$((U1+1))
	else
		ERR=$((ERR+1))
	fi
done

echo U0=$U0, U1=$U1, ERR=$ERR

exit 0

