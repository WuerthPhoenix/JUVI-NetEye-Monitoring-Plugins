#!/bin/bash
#
# Juergen Vigna - 2024/07/01 - Initial release
#
# Icinga/Nagios plugin to check how many shards of max_shards are open on node
#
# Copyright (C) 2024 Juergen Vigna
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Report bugs to:  juergen.vigna@wuerth-phoenix.com
#

PROGNAME=`basename $0 .sh`
PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0.0"
PLUGIN=$PROGNAME
ECHO=echo

TEMPDIR=/tmp
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

status=$STATE_OK

##
## Exit function
##
quit_status()
{
  if [ $status -eq $STATE_OK ]
  then
        $ECHO "OK - $msg"
  else
        if [ $status -eq $STATE_WARNING ]
        then
                $ECHO "WARNING - $msg"
        else
                $ECHO "CRITICAL - $msg"
        fi
  fi
  exit $status
}


##
## Usage function
##
print_usage() {
  $ECHO "Usage:"
  $ECHO "  $PROGNAME [-H <ELHOST>] [-p <ELPORT>] [-P <ELPROTO>] -N <ELNODE-NAME> [-w <WARNING-%>] [-c <CRITICAL-%>]"
  $ECHO "  $PROGNAME --help"
  $ECHO "  $PROGNAME --version"
  $ECHO "-H <ELHOST>      ... elasticsearch hostname or ip (default: $ELHOST)"
  $ECHO "-p <ELPORT>      ... elasticsearch tcp port (default: $ELPORT)"
  $ECHO "-P <ELPROTO>     ... elasticsearch protocol (default: $ELPROTO)"
  $ECHO "-N <ELNODE-NAME> ... elasticsearch node name"
  $ECHO "-w <WARNING-%>   ... warning usage value in percent of read max-value"
  $ECHO "-c <CRITICAL-%>  ... critical usage value in percent of read max-value"
}


##
## Help function
##
print_help() {
  $ECHO "$PLUGIN $REVISION"
  $ECHO ""
  $ECHO "This plugin checks for the status of elasticsearch snapshots"
  $ECHO ""
  print_usage
}


ELHOST=elasticsearch.neteyelocal
ELPORT=9200
ELPROTO=https
ELNODE=""

while [ $# -gt 0 ]
do
        case "$1" in
        --help)
                print_help
                exit $STATE_OK
                ;;
        -h)
                print_help
                exit $STATE_OK
                ;;
        --version)
                $ECHO "VERSION: $PLUGIN $REVISION"
                exit $STATE_OK
                ;;
        -V)
                $ECHO "VERSION: $PLUGIN $REVISION"
                exit $STATE_OK
                ;;
        -N)
                ELNODE=$2
                shift
                ;;
	-H)
		ELHOST=$2
		shift
		;;
	-p)
		ELPORT=$2
		shift
		;;
	-P)
		ELPROTO=$2
		shift
		;;
	-c)
		CRITICAL=$2
		shift
		;;
	-w)
		WARNING=$2
		shift
		;;
        *)
                print_usage
                exit $STATE_UNKNOWN
                ;;
        esac
        shift
done

if [ "$ELPROTO" != "http" -a "$ELPROTO" != "https" ]
then
	echo "ERROR: ELPROTO has to be http or https"
	exit 1
fi

if [ -z "$ELNODE" ]
then
	ELNODE=$(/usr/bin/curl -E /neteye/local/elasticsearch/conf/monitoring-certs/certs/NetEyeElasticCheck.crt.pem --key /neteye/local/elasticsearch/conf/monitoring-certs/certs/private/NetEyeElasticCheck.key.pem -s -X GET https://127.0.0.1:9200/ | jq .name | tr -d \")
	if [ -z "$ELNODE" ]
	then
		echo "UNKNOWN - Cannot read nodename from local elasticsearch, please specify manually"
		exit $STATE_UNKNOWN
	fi
fi

ELBASEURL=${ELPROTO}://${ELHOST}:${ELPORT}

TMPFILE=$(mktemp)
TMPFILE2=$(mktemp)
trap 'rm -f $TMPFILE $TMPFILE2; exit 1' 1 2 15
trap 'rm -f $TMPFILE $TMPFILE2' 0

/usr/bin/curl -E /neteye/local/elasticsearch/conf/monitoring-certs/certs/NetEyeElasticCheck.crt.pem --key /neteye/local/elasticsearch/conf/monitoring-certs/certs/private/NetEyeElasticCheck.key.pem -s -X GET "${ELBASEURL}/_cat/shards" 2>$TMPFILE2 >$TMPFILE

if [ -s $TMPFILE2 ]
then
	echo "UNKNOWN - Error in Elasticsearch query"
	cat $TMPFILE2
	exit 3
fi

totnum=$(cat $TMPFILE | wc -l)
totnumnode=$(cat $TMPFILE | grep $ELNODE | wc -l)
maxnum=$(/usr/bin/curl -E /neteye/local/elasticsearch/conf/monitoring-certs/certs/NetEyeElasticCheck.crt.pem --key /neteye/local/elasticsearch/conf/monitoring-certs/certs/private/NetEyeElasticCheck.key.pem -s -X GET "${ELBASEURL}/_cluster/settings" | jq .persistent.cluster.max_shards_per_node | tr -d \")
OUTPUT="OK - Node Usage is inside limits"
STATE=0

if [ -n "$CRITICAL" ]
then
	CRITVAL=$(expr $maxnum / 100 \* $CRITICAL)
	if [ $totnumnode -ge $CRITVAL ]
	then
		OUTPUT="CRITICAL - Node Usage is critical ($totnumnode > $CRITVAL [$CRITICAL%])"
		STATE=2
	fi
fi

if [ -n "$WARNING" ]
then
	WARNVAL=$(expr $maxnum / 100 \* $WARNING)
	if [ $totnumnode -ge $WARNVAL ]
	then
		OUTPUT="WARNING - Node Usage is warning ($totnumnode > $WARNVAL [$WARNING%])"
		STATE=1
	fi
fi

perfdata="total_shards=$totnum total_shards_$ELNODE=$totnumnode;$WARNVAL;$CRITVAL;0;$maxnum"

echo "$OUTPUT|$perfdata"
exit $STATE
