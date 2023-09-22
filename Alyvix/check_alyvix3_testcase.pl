#! /usr/bin/perl
# nagios: +epn
#
# check_alyvix3_testcase.pl - Get Monitoring Values from a single Alyvix3 Testcase
#
# Copyright (C) 2020-2023 Juergen Vigna
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
# Modified:
# 03/03/2023 VIJU: Support new Alyvix Service API
#

use strict;
use warnings;

use LWP::Simple;
use JSON;
use Data::Dumper;
use Getopt::Long;
use Date::Parse;
use HTTP::Cookies;
require HTTP::Request;
use LWP::UserAgent;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use REST::Client;
use MIME::Base64;
use URI::Encode qw( uri_encode );

my $PROGNAME = "check_alyvix3_testcase.pl";
my $VERSION  = "2.0.1";
sub print_help ();
sub print_usage ();

my @opt_verbose      = [];
my $opt_help         = undef;
my $opt_debug        = 0;
my $opt_host         = undef;
my $opt_hostname     = undef;
my $opt_testcase     = undef;
my $opt_testuser     = undef;
my $opt_timeout      = 0;
my $opt_testing      = 0;
my $opt_apibase      = 'v0/testcases';
my $opt_proxybase    = undef;
my $opt_statedir     = "/var/spool/neteye/tmp";
my $opt_userpass     = undef;
my $opt_oldapi       = 0;
my $opt_jwt          = 0;
my $opt_masterhostname = "icinga2-master.neteyelocal";

# Get the options
Getopt::Long::Configure('bundling');
GetOptions(
	'h'			=> \$opt_help,
	'v'			=> \@opt_verbose,
	'verbose'		=> \@opt_verbose,
	'help'			=> \$opt_help,
	'D'			=> \$opt_debug,
	'debug'			=> \$opt_debug,
	'testing'		=> \$opt_testing,
	'H=s'			=> \$opt_host,
	'host=s'		=> \$opt_host,
	'N=s'			=> \$opt_hostname,
	'hostname=s'		=> \$opt_hostname,
	'M=s'			=> \$opt_masterhostname,
	'masterhostname=s'		=> \$opt_masterhostname,
	'T=s'			=> \$opt_testcase,
	'testcase=s'		=> \$opt_testcase,
	'U=s'			=> \$opt_testuser,
	'testuser=s'		=> \$opt_testuser,
	't=i'			=> \$opt_timeout,
	'timeout=i'		=> \$opt_timeout,
	'd=s'			=> \$opt_statedir,
	'statedir=s'		=> \$opt_statedir,
	'p=s'			=> \$opt_userpass,
	'userpass=s'		=> \$opt_userpass,
	'A=s'			=> \$opt_apibase,
	'apibase=s'		=> \$opt_apibase,
	'P=s'			=> \$opt_proxybase,
	'useproxypass=s'	=> \$opt_proxybase,
	'J'			=> \$opt_jwt,
	'usejwt'		=> \$opt_jwt,
	) || print_help();

# If somebody wants the help ...
if ($opt_help) {
	print_help();
}

if (! defined($opt_host)) {
	print "ERROR: Missing Alyvix Server Host Name/IP (-H)!\n";
	exit 3;
}

if (! defined($opt_testcase)) {
	print "ERROR: Missing Testcase Name to check (-T)!\n";
	exit 3;
}

# Global Variables
my $request_url = "https://$opt_masterhostname:5665";

# --------------------------------------------------- helper -----------------------------------------
#

sub get_testcase_status {
	my $opt_host = shift;
	my $opt_testcase = shift;
	my $timeout = shift;
	my $opt_hostname = shift;
	my $base_url = "https://${opt_host}/${opt_apibase}/${opt_testcase}/";
	my $output_url = $base_url;
	if (defined($opt_proxybase)) {
		$output_url = "${opt_proxybase}/${opt_apibase}/${opt_testcase}";
	}
	my $id = undef;
	my $request;
	my $response;
	my $hash_content;
	my $useragent = LWP::UserAgent->new;
	$useragent->ssl_opts(
		SSL_verify_mode => SSL_VERIFY_NONE, 
		verify_hostname => 0
	);

	if (!$opt_oldapi) {
        	$base_url = "https://$opt_host/${opt_apibase}";
		if ($opt_jwt) {
			$response = $useragent->get($base_url, "Authorization" => "Bearer $opt_jwt");
		} else {
			$response = $useragent->get($base_url);
		}
        	if (!$response->is_success) {
        	        print "UNKNOWN - Could not connect to server (${base_url}) [", $response->status_line , "]\n";
        	        exit 3;
        	}
	        $hash_content = JSON::decode_json($response->content);
	        if (!defined($hash_content)) {
	                printf "UNKNOWN - cannot decode JSON string\n";
	                exit 3;
	        }
		if ($opt_debug) {
	        	printf "TESTCASES:%s\n",Data::Dumper::Dumper($hash_content);
		}
		my $t = $hash_content->{testcases};
		my @arr = @$t;
		my $size = @arr;
		my $n = 0;
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
		$base_url = "https://$opt_host/${opt_apibase}/" . $id . "/measures?testcase_case_screenshot=false";
	}
	if ($opt_jwt) {
		$response = $useragent->get($base_url, "Authorization" => "Bearer $opt_jwt");
	} else {
		$response = $useragent->get($base_url);
	}

	if (!$response->is_success) {
		print "UNKNOWN - Could not connect to server (${base_url}) [", $response->status_line , "]\n";
		exit 3;
	}

	my $json_content = $response->content;
	if (!defined($json_content)) {
		print "UNKNOWN - cannot access Alyvix Server API ($opt_testcase)\n";
		exit 3;
	}
	if ($opt_debug) {
		printf "%s\n", $json_content;
	}

	$hash_content = JSON::decode_json($json_content);
	if (!defined($hash_content)) {
		printf "UNKNOWN - cannot decode JSON string ($opt_testcase)\n";
		exit 3;
	}

	my $m;
	my @measures;
	if ($opt_oldapi) {
		$m = $hash_content->{measures};
		@measures = @$m;
	} else {
		@measures = @$hash_content;
	}
	my $URL;
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
	my $perfvalout;
	my $perfstate;
	my $perfexit;
	my $perfwarn;
	my $perfcrit;
	my $statestr = "OK";
	my $nprob = 0;
	my $ntot = 0;
	my $oldcode = "";
	my $oldstr = "OLD";
	my $now = time();
	my $probstr = "";
	my $outstr = "";
	my $verbstr = "";
	if (defined($opt_testuser)) {
		$testuser = $opt_testuser;
	}

	if ($size <= 0) {
		return 20;
	}

	my $statefile = $opt_statedir . "/alyvix3_testcase_${opt_host}_${opt_testcase}_${testuser}.state";

	if (-e $statefile) {
		open(my $fh_in, '<', $statefile)
			or die "Can't open \"$statefile\": $!\n";
		while (<$fh_in>) {
			chomp;
			$oldcode = "$_";
		}
		close($fh_in);
	}

	while($n < $size) {
		if (defined($opt_testuser)) {
			if (defined($measures[$n]->{domain_username})) {
				$testuser = $measures[$n]->{domain_username};
			} else {
				$testuser = $measures[$n]->{username};
			}
			if ($testuser ne $opt_testuser) {
				$n++;
				next;
			}
		}
		if (!defined($testcode)) {
			$testcode     = $measures[$n]->{test_case_execution_code};
			if ($opt_debug) { print "First TESTCODE: $testcode\n"; }
			$teststate    = $measures[$n]->{test_case_state};
			$testduration = $measures[$n]->{test_case_duration_ms};
			$testtime     = substr($measures[$n]->{timestamp_epoch}, 0, 10);
		} elsif ($testcode ne $measures[$n]->{test_case_execution_code}) {
			if ($opt_debug) { print "TESTCODE: $testcode" . " : " . $measures[$n]->{test_case_execution_code} . "\n"; }
			my $newtesttime = substr($measures[$n]->{timestamp_epoch}, 0, 10);
			if ($opt_debug) { print "Changed TESTCODE: $testtime < $newtesttime\n"; }
			if ($testtime > $newtesttime) {
				$n++;
				next;
			}
			# Reset all newer data available
			$perfout = "";
			$probstr = "";
			$verbstr = "";
			$ntot    = 0;
			$nprob   = 0;
			$testcode     = $measures[$n]->{test_case_execution_code};
			if ($opt_debug) { print "New TESTCODE: $testcode\n"; }
			$teststate    = $measures[$n]->{test_case_state};
			$testduration = $measures[$n]->{test_case_duration_ms};
			$testtime     = substr($measures[$n]->{timestamp_epoch}, 0, 10);
		}
	
		if ($measures[$n]->{transaction_name} ne $measures[$n]->{transaction_alias}) {
			$perfname  = $measures[$n]->{transaction_name} . "_" . $measures[$n]->{transaction_alias};
		} else {
			$perfname  = $measures[$n]->{transaction_name};
		}
		$perfvalue = $measures[$n]->{transaction_performance_ms};
		$perfstate = $measures[$n]->{transaction_state};
		$perfwarn  = $measures[$n]->{transaction_warning_ms};
		$perfexit = $measures[$n]->{transaction_exit};
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
		if ($opt_debug) { print "PERFSTATE:${perfname}->${perfstate}:\n"; }
		if ($perfwarn && $perfcrit && ($perfstate != 0) && defined($perfvalue)) {
			$ntot++;
			if ($perfstate == 1) {
				$nprob++;
				$probstr .= ",$perfname:WARNING";
			} elsif ($perfstate == 2) {
				$nprob++;
				$probstr .= ",$perfname:CRITICAL";
			} else {
				$nprob++;
				$probstr .= ",$perfname:UNKNOWN";
			}
		} elsif ($perfexit =~ /fail/) {
			$nprob++;
			$probstr .= ",$perfname:FAIL";
		} elsif ($perfwarn && $perfcrit) {
			$ntot++;
		}
		if ($#opt_verbose) {
			my $pv;
			if (defined($perfvalue)) {
				$pv = $perfvalue;
			} else {
				$pv = "[n/a]";
			}
			if ($perfwarn && $perfcrit) {
				$perfvalout = "${pv}ms/$perfwarn/$perfcrit";
			} else {
				$perfvalout = "${pv}ms";
			}
			if (($#opt_verbose > 1) || ($perfwarn && $perfcrit)) {
				if ($perfstate == 0) {
					$verbstr .= "OK - $perfname ($perfvalout)\n";
				} elsif ($perfstate == 1) {
					$verbstr .= "WARNING - $perfname ($perfvalout)\n";
				} elsif ($perfstate == 2) {
					$verbstr .= "CRITICAL - $perfname ($perfvalout)\n";
				} else {
					$verbstr .= "UNKNOWN - $perfname ($perfvalout)";
				}
			}
		}
		$n++;
	}

	if (!defined($testcode)) {
		$teststate = 3;
		print "UNKNOWN - Could not find any performace data for the testcase $opt_testcase!";
		exit 3;
	}

	if ($teststate == 1) {
		$statestr = "WARNING";
	} elsif ($teststate == 2) {
		$statestr = "CRITICAL";
	} elsif ($teststate > 2) {
		$statestr = "UNKNOWN";
	}

	if ($timeout > 0) {
		my $timediff = $now - $testtime;
		if ($timediff > $timeout) {
			if ($opt_debug) {
				print "TIMEOUT $timediff > $timeout\n";
			}
			$statestr = "UNKNOWN";
			$teststate = 3;
			$oldcode = $testcode;
			$oldstr = "TIMEOUT";
		}
	}

	if ($opt_oldapi) {
		$URL = "${output_url}/reports/?runcode=${testcode}";
	} else {
		$URL = "/neteye/alyvix/testcases?nodeName=${opt_hostname}&testcaseId=${id}&tab=reports&runcode=${testcode}";
	}
	my $testtimestr = scalar localtime $testtime;
	if ($opt_debug) {
		print "$testcode -> $oldcode\n";
	}
	if ($testcode ne $oldcode) {
		print "${statestr} - $nprob problem(s)${probstr} (Last Run: $testtimestr) (<a href='${URL}' target='_blank'>Log</a>) | duration=${testduration}ms;;;0;${perfout}\n";
		if ($#opt_verbose && defined($verbstr)) {
			print "$verbstr";
		}
		open(my $fh_out, '>', $statefile)
			or die "Can't create \"$statefile\": $!\n";
		print($fh_out "${testcode}\n");
		close($fh_out);
	} elsif ($oldstr eq "TIMEOUT") {
		print "${statestr} - $nprob problem(s)${probstr} [$oldstr] (Last Run: $testtimestr) (<a href='${URL}' target='_blank'>Log</a>)\n";
		if ($#opt_verbose && defined($verbstr)) {
			print "$verbstr";
		}
	} else {
		print "${statestr} - $nprob problem(s)${probstr} [OLD] (Last Run: $testtimestr) (<a href='${URL}' target='_blank'>Log</a>)\n";
		if ($#opt_verbose && defined($verbstr)) {
			print "$verbstr";
		}
	}
	exit $teststate;
}

sub print_help() {
	printf "%s, Version %s\n",$PROGNAME, $VERSION;
	print "Copyright (c) 2020-2023 Juergen Vigna\n";
	print "This program is licensed under the terms of the\n";
	print "GNU General Public License\n(check source code for details)\n";
	print "\n";
	printf "Get monitoring results for a Testcase from Alyvix3 Server\n";
	print "\n";
	print_usage();
	print "\n";
	print " -V (--version)     Programm version\n";
	print " -h (--help)        usage help\n";
	print " -v (--verbose)     verbose output\n";
	print " -D (--debug)       debug output\n";
	print " -H (--host)        Alyvix3 Server hostname/ip\n";
	print " -N (--hostname)    Alyvix3 Server hostname for report-url\n";
	print " -M (--masterhostname) Alyvix3 Master Server hostname for Icinga2 Web Access (default: $opt_masterhostname)\n";
	print " -T (--testcase)    Alyvix3 Testcase Name\n";
	print " -U (--testuser)    Alyvix3 Testcase user (default: ALL_USERS)\n";
	print " -t (--timeout)     Alyvix3 Testcase values older then timeout gives UNKNOWN (default: $opt_timeout)\n";
	print " -d (--statedir)    Directory where to write the statefiles (default: $opt_statedir)\n";
	print " -p (--userpass)    User:Password for Icinga2 Web access\n";
	print " -J (--usejwt)      Get JWT Token from NetEye API and use it on Alyvix API (use -p option)\n";
	print " -A (--apibase)     Alyvix3 Server API BaseURL (default: $opt_apibase)\n";
	print " -P (--proxypass)   The Output Url to access logs uses a proxypass\n";
	print "\n";
	exit 0;
}

sub print_usage() {
	print "Usage: \n";
	print "  $PROGNAME (-H|--host <hostname/ip>) (-T|--testcase <string>) (-p|--userpass <user:pass>) [-U|--testuser <user>] [-t|--timeout <int>] [-d|--statedir <dir>] [-A|--apibase <apibase>] [-P|--proxypass <proxy-pre>] [-M|--masterhostname <hostname>]\n";
	print "  $PROGNAME [-h | --help]\n";
	print "  $PROGNAME [-V | --version]\n";
}

sub get_api_version {
	my $opt_host = shift;

	my $base_url = "https://${opt_host}";
	my $useragent = LWP::UserAgent->new;
	$useragent->ssl_opts(
		SSL_verify_mode => SSL_VERIFY_NONE, 
		verify_hostname => 0
	);
	my $request = HTTP::Request->new('GET', $base_url);
	my $response = $useragent->request($request);

	if (!defined($response->content)) {
		print "UNKNOWN - Could not connect to alyvix server (${base_url}) [", $response->status_line , "]\n";
		exit 3;
	}

	if ($response->content =~ /token is missing/) {
		return 0;
	}
	return 1;
}

sub get_jwt_token {
	my $opt_host = shift;
	my $opt_user = shift;
	my $opt_password = shift;

	my $base_url = "https://${opt_host}";
	my $ua = new LWP::UserAgent();
	$ua->ssl_opts(
		SSL_verify_mode => SSL_VERIFY_NONE, 
		verify_hostname => 0
	);
	my $URL;
	my $response;
	my $ICINGAWEB2_COOKIE;
	my $CSRF_TOKEN;
	my $CSRF_TOKEN_URL_FORMATTED;

	#
	# pre login
	#
	$URL = ${base_url} . "/neteye/authentication/login";

	my $cookie_jar = HTTP::Cookies->new( );
	$cookie_jar->set_cookie(0,'icingaweb2-tzo', '7200-1','/','',80,0,0,86400,0);
	$ua->cookie_jar($cookie_jar);
	$response = $ua->get($URL,
		'Host' => ${opt_host},
		'Upgrade-Insecure-Requests' => 1,
		'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36',
		'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
		'Sec-Fetch-Site' => 'none',
		'Sec-Fetch-Mode' => 'navigate',
		'Sec-Fetch-User' => '?1',
		'Sec-Fetch-Dest' => 'document',
		'Sec-Ch-Ua' => '"Not:A-Brand";v="99","Chromium";v="112"',
		'Sec-Ch-Ua-Mobile' => '?0',
		'Sec-Ch-Ua-Platform' => '"Linux"',
		'Accept-Encoding' => 'gzip,deflate',
		'Accept-Language' => 'en-US,en;q=0.9',
		'Connection' => 'close');
	if (!defined($response->content)) {
		print "UNKNOWN - Could not connect to neteye login (${base_url}) [", $response->status_line , "]\n";
		exit 3;
	}
	if ($opt_debug) {
		print "\nCOOKIES:" . $response->headers()->header("Set-Cookie") . "\n";
	}
	if ($ICINGAWEB2_COOKIE = $response->headers()->header("Set-Cookie") =~ /.*Icingaweb2=(.*); path.*/) {
		$ICINGAWEB2_COOKIE=$1;
		if ($opt_debug) {
			print $ICINGAWEB2_COOKIE;
		}
	} else {
		print "UNKNOWN - Could not extract Icingaweb2 Cookie (", $response->headers()->header("Set-Cookie") , ")\n";
		exit 3;
	}

	my @content = split /^/, $response->content;
	my @TOKENLINE = grep(/form_login_CSRFToken/, @content);
	if ($TOKENLINE[0] =~ / value="([^"]*)"/) {
		$CSRF_TOKEN=$1;
		$CSRF_TOKEN_URL_FORMATTED=uri_encode($CSRF_TOKEN);
	} else {
		print "UNKNOWN - Could not extract CSRF_TOKEN (", @TOKENLINE, ")\n";
		exit 3;
	}

	#
	# login request
	#

	$URL = "/neteye/authentication/login";
	my $client = REST::Client->new();
	$client->setHost($base_url);
	$client->getUseragent()->ssl_opts(
		SSL_verify_mode => SSL_VERIFY_NONE,
		verify_hostname => 0
	);
	$client->addHeader('Host', ${opt_host});
	$client->addHeader('Sec-Ch-Ua', '"Not:A-Brand";v="99","Chromium";v="112"');
	$client->addHeader('X-Icinga-Windowid', 'mquxzfpsojyc');
	$client->addHeader('X-Icinga-Accept', 'text/html');
	$client->addHeader('Sec-Ch-Ua-Mobile', '?0');
	$client->addHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36');
	$client->addHeader('Content-Type', 'application/x-www-form-urlencoded;charset=UTF-8');
	$client->addHeader('Accept', '*/*');
	$client->addHeader('X-Requested-With', 'XMLHttpRequest');
	$client->addHeader('X-Icinga-Container', 'layout');
	$client->addHeader('Sec-Ch-Ua-Platform', '"Linux"');
	$client->addHeader('Origin', "https://${opt_host}");
	$client->addHeader('Sec-Fetch-Site', 'same-origin');
	$client->addHeader('Sec-Fetch-Mode', 'cors');
	$client->addHeader('Sec-Fetch-Dest', 'empty');
	$client->addHeader('Referer', "https://${opt_host}/neteye/authentication/login");
	$client->addHeader('Accept-Encoding', 'gzip,deflate');
	$client->addHeader('Accept-Language', 'en-US,en;q=0.9');
	$client->addHeader('Connection', 'close');
	$client->addHeader('Cookie', "icingaweb2-tzo=7200-1; Icingaweb2=$ICINGAWEB2_COOKIE");
	my $data = "username=${opt_user}&password=${opt_password}&rememberme=0&redirect=&formUID=form_login&CSRFToken=${CSRF_TOKEN_URL_FORMATTED}&btn_submit=Login";
	$client->POST($URL, $data);

	my $status = $client->responseCode();
	$response = $client->responseContent();

	if ($opt_debug) {
		printf "CLIENT:%s\n",Data::Dumper::Dumper($client);
		printf "RESPONSE:%s:%s\n",$client->responseHeader("Set-Cookie");
	}
	if (!defined($response)) {
		print "UNKNOWN - Could not make neteye login (${base_url}) [", $status, "]\n";
		exit 3;
	}
	if ($ICINGAWEB2_COOKIE = $client->responseHeader("Set-Cookie") =~ /.*Icingaweb2=(.*); path.*/) {
		$ICINGAWEB2_COOKIE=$1;
	} else {
		print "UNKNOWN - Could not extract Icingaweb2 Cookie (", $response->headers()->header("Set-Cookie") , ")\n";
		exit 3;
	}

	#
	# JWT Request
	#

	if ($opt_debug) {
		print "COOKIE:$ICINGAWEB2_COOKIE\n";
	}
	$URL = ${base_url} . "/neteye/api/v1/jwt";
	$ua = new LWP::UserAgent();
	$ua->ssl_opts(
		SSL_verify_mode => SSL_VERIFY_NONE,
		verify_hostname => 0
	);
	$response = $ua->get($URL,
		'Host' => ${opt_host},
		'Sec-Ch-Ua' => '"Not:A-Brand";v="99","Chromium";v="112"',
		'Sec-Ch-Ua-Mobile' => '?0',
		'Sec-Ch-Ua-Platform' => '"Linux"',
		'Upgrade-Insecure-Requests' => '1',
		'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36',
		'Accept' => '*/*',
		'Sec-Fetch-Site' => 'none',
		'Sec-Fetch-Mode' => 'navigate',
		'Sec-Fetch-User' => '?1',
		'Sec-Fetch-Dest' => 'document',
		'Accept-Encoding' => 'gzip,deflate',
		'Accept-Language' => 'en-US,en;q=0.9',
		'Cookie' => "icingaweb2-tzo=7200-1; Icingaweb2=$ICINGAWEB2_COOKIE",
		'Connection' => 'close');
	if (!defined($response->content)) {
		print "UNKNOWN - Could not connect to neteye login (${base_url}) [", $response->status_line , "]\n";
		exit 3;
	}

	my $json_content = JSON::decode_json($response->content);
	if (!defined($json_content->{token})) {
		print "UNKNOWN - Could get JWT Token [", $response->status_line , "]\n";
		exit 3;
	}
	return $json_content->{token};
}

#
# ------------------------------------------ START MAIN --------------------------------------------
#

$opt_oldapi = get_api_version($opt_host);
if (!$opt_oldapi) {
	if (! defined($opt_hostname)) {
		print "ERROR: Missing Alyvix Server Hostname (-N)!\n";
		exit 3;
	}

	if ($opt_jwt) {
		if (! defined($opt_userpass)) {
			print "ERROR: Missing Icinga2 Web credentials (-p)!\n";
			exit 3;
		}
		my @cred = split ":", $opt_userpass;
		my $u = $cred[0];
		my $p = $cred[1];
		$opt_jwt = get_jwt_token($opt_masterhostname,$u,$p);
		if ($#opt_verbose > 1) {
			print "JWTTOKEN=$opt_jwt\n";
		}
	}
}


get_testcase_status($opt_host, $opt_testcase, $opt_timeout, $opt_hostname);
exit 3;
