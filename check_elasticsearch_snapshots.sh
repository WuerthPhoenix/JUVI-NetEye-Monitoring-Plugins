#!/bin/bash
#
# Juergen Vigna - 2023/02/28 - Initial release
#
# Icinga/Nagios plugin to check for the snapshot status of elasticsearch
#
# Copyright (C) 2023 Juergen Vigna
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

PROGNAME=`basename $0`
PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0.0"
PLUGIN="check_elasticsearch_snapshots"
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
  $ECHO "  $PROGNAME -r <snapshot_repository_name> [ -s <snapshot_basename> ] [-d <number-days-back>]"
  $ECHO "  $PROGNAME --help"
  $ECHO "  $PROGNAME --version"
  $ECHO "-r <snapshot_repository_name> ... name of elasticsearch snapshot backup repostiory"
  $ECHO "-s <snapshot_basename>        ... base name of snapshop to check for (default: ALL)"
  $ECHO "-d <number-days-back>         ... numbers of days back to look for status of snapshots (default: 3)"
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


DAYS=3
ELHOST=elasticsearch.neteyelocal
ELPORT=9200
ELPROTO=https

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
        -d)     DAYS=$2
                shift
                ;;
        -s)
                ELSNAPSHOTBASENAME=$2
                shift
                ;;
        -r)
                ELREPONAME=$2
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

if [ -z "$ELREPONAME" ]
then
	echo "ERROR - Specify the Repository Name to proceed -r option"
	exit $STATE_UNKNOWN
fi

ELBASEURL=${ELPROTO}://${ELHOST}:${ELPORT}

TMPFILE=$(mktemp)
trap 'rm -f $TMPFILE; exit 1' 1 2 15
trap 'rm -f $TMPFILE' 0

DATEREGEX="$(date +%Y.%m.%d)"
i=0
dd=$(expr $DAYS - 1)
while [ $i -lt $dd ]
do
	i=$(expr $i + 1)
	DATEREGEX="${DATEREGEX}|$(date +%Y.%m.%d -d "-$i day")"
done

/usr/bin/curl -E /neteye/local/elasticsearch/conf/monitoring-certs/certs/NetEyeElasticCheck.crt.pem --key /neteye/local/elasticsearch/conf/monitoring-certs/certs/private/NetEyeElasticCheck.key.pem -s -X GET "${ELBASEURL}/_snapshot/${ELREPONAME}/_all?pretty" | jq '.snapshots[] | [.snapshot,.state] | join(":")' | egrep $DATEREGEX > $TMPFILE

if [ -n "$ELSNAPSHOTBASENAME" ]
then
	oknum=$(cat $TMPFILE | grep "$ELSNAPSHOTBASENAME" | grep -c SUCCESS)
	totnum=$(cat $TMPFILE | grep "$ELSNAPSHOTBASENAME" | wc -l)
else
	oknum=$(cat $TMPFILE | grep -c SUCCESS)
	totnum=$(cat $TMPFILE | wc -l)
fi


if [ $oknum -eq $totnum ]
then
	echo "OK - All snapshots with status SUCCESS"
	status=$STATE_OK
elif [ $oknum -gt 0 ]
then
	echo "WARNING - Some snapshots with errors"
	status=$STATE_WARNING
else
	echo "CRITICAL - Snapshots with errors"
	status=$STATE_CRITICAL
fi

if [ -n "$ELSNAPSHOTBASENAME" ]
then
	cat $TMPFILE | grep "$ELSNAPSHOTBASENAME" | tr -d \" | sed -e 's/:/ -> /g'
else
	cat $TMPFILE | tr -d \" | sed -e 's/:/ -> /g'
fi
exit $status
