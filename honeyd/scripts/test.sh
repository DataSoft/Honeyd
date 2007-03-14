DATE=`date`
echo "$DATE: Started From $1 Port $2" >> /tmp/log
echo SSH-1.5-2.40
while read name
do
	echo "$name" >> /tmp/log
        echo "$name"
done
