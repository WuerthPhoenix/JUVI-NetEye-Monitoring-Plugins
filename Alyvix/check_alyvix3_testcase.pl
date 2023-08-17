#! /usr/bin/perl
# nagios: +epn
#
# check_alyvix3_testcase.pl - Get Monitoring Values from Alyvix3 Server API
#
# Copyright (C) 2020 Juergen Vigna
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
#

use strict;
use warnings;

use LWP::Simple;
use JSON;
use Data::Dumper;
use Getopt::Long;
use Date::Parse;
require HTTP::Request;
use LWP::UserAgent;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);

my $PROGNAME = "check_alyvix3_testcase.pl";
my $VERSION  = "1.0.0";
sub print_help ();
sub print_usage ();

my $opt_verbose  = 0;
my $opt_help     = undef;
my $opt_debug    = 0;
my $opt_host     = undef;
my $opt_testcase = undef;
my $opt_testuser = undef;
my $opt_timeout  = 0;
my $opt_testing  = 0;
my $opt_oldapi   = 0;

# Get the options
Getopt::Long::Configure('bundling');
GetOptions(
	'h'			=> \$opt_help,
	'v'			=> \$opt_verbose,
	'verbose'		=> \$opt_verbose,
	'help'			=> \$opt_help,
	'D'			=> \$opt_debug,
	'debug'			=> \$opt_debug,
	'testing'		=> \$opt_testing,
	'H=s'			=> \$opt_host,
	'host=s'		=> \$opt_host,
	'T=s'			=> \$opt_testcase,
	'testcase=s'		=> \$opt_testcase,
	'U=s'			=> \$opt_testuser,
	'testuser=s'		=> \$opt_testuser,
	't=i'			=> \$opt_timeout,
	'timeout=i'		=> \$opt_timeout,
	'o'			=> \$opt_oldapi,
	'oldapi'		=> \$opt_oldapi,
	) || print_help();

# If somebody wants the help ...
if ($opt_help) {
	print_help();
}

if (! defined($opt_host)) {
	print "ERROR: Missing Alyvix3 Server Host Name/IP!\n";
	exit 3;
}

if (! defined($opt_testcase)) {
	print "ERROR: Missing Alyvix3 Testcase Name!\n";
	exit 3;
}

my $base_url;
my $request;
my $response;
my $json_content;
my $hash_content;
my $useragent = LWP::UserAgent->new;
$useragent->ssl_opts(
    SSL_verify_mode => SSL_VERIFY_NONE, 
    verify_hostname => 0
);

if ($opt_oldapi) {
	$base_url = "https://$opt_host/v0/testcases/$opt_testcase/";
} else {
	$base_url = "https://$opt_host/testcases";
	$request = HTTP::Request->new('GET', $base_url);
	$response = $useragent->request($request);
	if (!$response->is_success) {
		print "UNKNOWN - Could not connect to server (${base_url}) [", $response->status_line , "]\n";
		exit 3;
	}
	$hash_content = JSON::decode_json($response->content);
	if (!defined($hash_content)) {
		printf "UNKNOWN - cannot decode JSON string\n";
		exit 3;
	}
	my $t = $hash_content->{testcases};
	my @arr = @$t;
	my $size = @arr;
	my $n = 0;
	my $id = undef;
	my $tname;
	while (($n lt $size) && !defined($id)) {
		$tname = $arr[$n]->{name};
		if ($tname =~ /$opt_testcase/) {
			$id = $arr[$n]->{id};
		}
		$n++;
	}
	if (!defined($id)) {
		print "UNKNOWN - Testcase $opt_testcase not found";
		exit 3;
	}
	$base_url = "https://$opt_host/testcases/" . $id . "/measures?testcase_case_screenshot=false";
}

$request = HTTP::Request->new('GET', $base_url);
$response = $useragent->request($request);
if (!$response->is_success) {
	print "UNKNOWN - Could not connect to server (${base_url}) [", $response->status_line , "]\n";
	exit 3;
}

$json_content = $response->content;
if (!defined($json_content)) {
	print "UNKNOWN - cannot access Alyvix Server API\n";
	exit 3;
}
if ($opt_debug) {
	printf "%s\n", $json_content;
}

$hash_content = JSON::decode_json($json_content);
if (!defined($hash_content)) {
	printf "UNKNOWN - cannot decode JSON string\n";
	exit 3;
}

my $tmpfile = "/var/tmp/alyvix3_last_testcase_code";
my @measures = @$hash_content;
my $size = @measures;
my $n = 0;
my $testuser = "ALL";
my $teststate;
my $testduration;
my $testcode = undef;
my $testtime;
my $perfout = "";
my $perfname;
my $perfvalue = 0;
my $perfstate;
my $perfwarn;
my $perfcrit;
my $statestr = "OK";
my $nprob = 0;
my $oldcode = "";
my $oldstr = "OLD";
my $now = time();

while($n lt $size) {
	if (defined($opt_testuser)) {
		$testuser = $measures[$n]->{username};
		if ($testuser != $opt_testuser) {
			$n++;
			next;
		}
	}
	if (!defined($testcode)) {
		$teststate    = $measures[$n]->{test_case_state};
		$testduration = $measures[$n]->{test_case_duration_ms};
		$testcode     = $measures[$n]->{test_case_execution_code};
		$testtime     = substr($measures[$n]->{timestamp_epoch}, 0, 10);
		$tmpfile .= "-$opt_testcase-$testuser.txt";
		if (-e $tmpfile) {
			open(my $fh_in, '<', $tmpfile)
				or die "Can't open \"$tmpfile\": $!\n";
			while (<$fh_in>) {
				chomp;
				$oldcode = "$_";
			}
			close($fh_in);
		}

	}
	
	$perfname  = $measures[$n]->{transaction_name};
	$perfvalue = $measures[$n]->{transaction_performance_ms};
	$perfstate = $measures[$n]->{transaction_state};
	$perfwarn  = $measures[$n]->{transaction_warning_ms};
	if (!defined($perfwarn) || $perfwarn !~ /[0-9]*/) {
		$perfwarn = "";
	}
	$perfcrit  = $measures[$n]->{transaction_critical_ms};
	if (!defined($perfcrit) || $perfcrit !~ /[0-9]*/) {
		$perfcrit = "";
	}

	if (defined($perfvalue) && $perfwarn && $perfcrit) {
		$perfout .= " ${perfname}=${perfvalue}ms;${perfwarn};${perfcrit};0;";
	}
	if ($perfstate ne 0) {
		$nprob++;
	}
	$n++;
}

if (!defined($testcode)) {
	print "UNKNOWN - Could not find any performace data for the testcase $opt_testcase!\n";
	exit 3;
}

if ($teststate == 1) {
	$statestr = "WARNING";
} elsif ($teststate == 2) {
	$statestr = "CRITICAL";
} elsif ($teststate > 2) {
	$statestr = "UNKNOWN";
}

if ($opt_timeout > 0) {
	my $timediff = $now - $testtime;
	if ($timediff > $opt_timeout) {
		if ($opt_verbose || $opt_debug) {
			print "TIMEOUT $timediff > $opt_timeout\n";
		}
		$statestr = "UNKNOWN";
		$teststate = 3;
		$oldcode = $testcode;
		$oldstr = "TIMEOUT";
	}
}

if ($opt_debug) {
	print "$testcode -> $oldcode\n";
}
if ($opt_testing) {
	print "${statestr} - $nprob transaction in Problem Status (<a href='https://${opt_host}/v0/testcases/${opt_testcase}/reports/?runcode=${testcode}' target='_blank'>Log</a>) | duration=${testduration}ms;;;0;${perfout}\n";
} elsif ($testcode ne $oldcode) {
	open(my $fh_out, '>', $tmpfile)
		or die "Can't create \"$tmpfile\": $!\n";
	print($fh_out "${testcode}\n");
	close($fh_out);
	print "${statestr} - $nprob transaction in Problem Status (<a href='https://${opt_host}/v0/testcases/${opt_testcase}/reports/?runcode=${testcode}' target='_blank'>Log</a>) | duration=${testduration}ms;;;0;${perfout}\n";
} else {
	print "${statestr} - $nprob transaction in Problem Status [$oldstr] (<a href='https://${opt_host}/v0/testcases/${opt_testcase}/reports/?runcode=${testcode}' target='_blank'>Log</a>)\n";
}
exit $teststate;

# --------------------------------------------------- helper -----------------------------------------
#

sub print_help() {
	printf "%s, Version %s\n",$PROGNAME, $VERSION;
	print "Copyright (c) 2020 Juergen Vigna\n";
	print "This program is licensed under the terms of the\n";
	print "GNU General Public License\n(check source code for details)\n";
	print "\n";
	printf "Get monitoring results for a Testcase from Alyvix3 Server\n";
	print "\n";
	print_usage();
	print "\n";
	print " -V (--version)   Programm version\n";
	print " -h (--help)      usage help\n";
	print " -v (--verbose)   verbose output\n";
	print " -D (--debug)     debug output\n";
	print " -H (--host)      Alyvix3 Server hostname/ip\n";
	print " -T (--testcase)  Alyvix3 Testcase name\n";
	print " -U (--testuser)  Alyvix3 Testcase user (default: ALL_USERS)\n";
	print " -t (--timeout)   Alyvix3 Testcase values older then timeout gives UNKNOWN (default: $opt_timeout)";
	print " -o (--oldapi)    Use the old AlyvixServer API instead of the new AlyvixService API";
	print "\n";
	exit 0;
}

sub print_usage() {
	print "Usage: \n";
	print "  $PROGNAME [-H|--dbhost <hostname/ip>] [-d|--dbname <databasename>] [-u|--dbuser <username>] [-p|--dbpass <password>] [-T|--testonly] [-U|--apiuser <user>] [-S|--apipass <password>] [-o|--oldapi]\n";
	print "  $PROGNAME [-h | --help]\n";
	print "  $PROGNAME [-V | --version]\n";
}
