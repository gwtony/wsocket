#!/bin/sh
stats() {
	awk -F '[\\,,:]' '
	BEGIN {
		succ=error=recv=time=0;
	} $2 ~/(EOF|EXCEPTION)/ {
		recv+=$6;
		time+=$8;
		total++;
		if($2 ~ /EOF/) {
			succ++;
		} else if($2 ~ /EXCEPTION/) {
			error++;
		}
	} END {
		run_time='$end_time'-'$start_time';
		printf "\r\nDocument Path:\t\t/%s.html\n", "'$SIZE'";
		printf "Document Length:\t%s\n\n", "'$SIZE'";
		printf "Concurrency Level:\t%d\n", '$C';
		printf "Time taken for tests:\t%.3lf seconds\n",run_time;
		printf "Complete requests:\t%d\n",succ;
		printf "Failed requests:\t%d\n",error;
		printf "Total transferred:\t%d bytes\n",recv;
		printf "Requests per second:\t%.2lf [#/sec]\n",total/run_time;
		printf "Time per request:\t%.3lf [ms]\n",time/total;
		printf "Time per request:\t%.3lf [ms] (mean, across all concurrent requests)\n",(run_time*1000)/total;
		printf "Transfer rate:\t\t%.2lf [Kbytes/sec] (mean, per request)\n",(recv/1024)/(time/1000);
		printf "Transfer rate:\t\t%.2lf [Kbytes/sec] (mean, across all concurrent requests)\n",(recv/1024)/run_time;
	}' ${LOGDIR}/*.info.log
}

export WSOCKET_KEEPALIVE="0"
export WSOCKET_SERVER="10.75.13.92"
export WSOCKET_PORT="8002"
export WSOCKET_CERT_CA="/tmp/ca.crt"
export WSOCKET_CERT_SERVER="/tmp/client.crt"
LOGDIR=/data0/changtuo/tmp
PROMAX=50
N=1
C=1
SIZE="8k"
runback=0
rm $LOGDIR/*.log

if [[ $1 -gt 0 ]];then
	N=$1
fi
if [[ $2 -gt 0 ]];then
	C=$2
fi
if [ -n "$3" ];then
	SIZE=$3
fi
if [ "$4" = "-k" ];then
	export WSOCKET_KEEPALIVE="1"
fi
if [[ $5 -gt 0 ]];then
	runback=$5
fi

num=0;
prono=`expr $N / $C`
remainder=`expr $N % $C`
if [ $remainder -gt 0 ];then
	prono=$((prono+1));
fi
if [ $runback -gt 0 -a $prono -gt $PROMAX ];then
	prono=$PROMAX
fi

start_time=`date -d 'now' +%s.%N`	
for((i=0;i<prono;i++));
do
	INFO=$LOGDIR/$i.info.log
	ERROR=$LOGDIR/$i.error.log
	> $ERROR
	> $INFO
	count=$C
	if [ $((num+C)) -gt $N ];then 
		count=$((N-num));
	fi
	num=$((num+count));
	if [ $runback -gt 0 ];then
		T_WS=`./client ${count} http://10.75.13.92/${SIZE}.html 2>${ERROR} >${INFO} &`
		echo -e "prono:${i}\tcount:${count}\t${T_WS}"
	else
		./client ${count} http://10.75.13.92/${SIZE}.html 2>${ERROR} >${INFO}
		echo -e "Completed " $num "requests"
	fi
done
end_time=`date -d 'now' +%s.%N`

if [ $runback -le 0 ];then
	stats
fi

