#! /bin/sh
#
if [ "$1" = "-V" ]
then
	if [ -z "$2" ]
	then
		. /etc/profile.d/neteye-DNF.sh
		VERSION=$DNF0
	else
		VERSION=$2
	fi
fi

state=0
TMPFILE=$(mktemp)
trap 'rm -f $TMPFILE; exit 1' 1 2 15
trap 'rm -f $TMPFILE' 0

for i in $(cat /etc/neteye-cluster | jq '.Nodes[].hostname, .VotingOnlyNode.hostname, .ElasticOnlyNodes[].hostname' 2>/dev/null | tr -d \")
do
        if [ "$i" != "null" ]
        then
                RELEASE=$(ssh $i cat /etc/neteye-release)
		if [ -n "$VERSION" ]
		then
                	printf "%-30s: %s\n" $i "$RELEASE" >>$TMPFILE
			ver=$(echo "$RELEASE" | sed -e 's/[^0-9\.]*//g')
			if [ "$ver" != "$VERSION" ]
			then
				state=1
			fi
		else
                	printf "%-30s: %s\n" $i "$RELEASE"
		fi
        fi
done
for i in /etc/neteye-satellite.d/*/*.conf
do
        HOST=$(cat $i | jq .fqdn | tr -d \")
        RELEASE=$(ssh $HOST cat /etc/neteye-release)
	if [ -n "$VERSION" ]
	then
		printf "%-30s: %s\n" $HOST "$RELEASE" >>$TMPFILE
		ver=$(echo "$RELEASE" | sed -e 's/[^0-9\.]*//g')
		if [ "$ver" != "$VERSION" ]
		then
			state=1
		fi
	else
		printf "%-30s: %s\n" $HOST "$RELEASE"
	fi
done

if [ -n "$VERSION" ]
then
	if [ $state -ne 0 ]
	then
		echo "WARNING - Some nodes have wrong Version $VERSION"
		cat $TMPFILE
		exit 1
	fi
	echo "OK - All nodes on Version $VERSION"
	cat $TMPFILE
	exit 0
fi
