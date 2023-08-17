#! /usr/bin/perl
# nagios: +epn
#
# check_elastic_fleet_agents_status.pl - Check the status of the Agents registered in Elastic-Fleet-Server
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
#
#WP START
BEGIN {
  $ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;
  eval {
    # required for new IO::Socket::SSL versions
    require IO::Socket::SSL;
    IO::Socket::SSL->import();
    IO::Socket::SSL::set_ctx_defaults( SSL_verify_mode => 0 );
  };
};
#WP END

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

my $PROGNAME = "check_elastic_fleet_agents_status.pl";
my $VERSION  = "1.0.0";
sub print_help ();
sub print_usage ();

my @opt_verbose  = [];
my $opt_help     = undef;
my $opt_debug    = 0;
my $opt_host     = "kibana.neteyelocal";
my $opt_port     = "5601";
my $opt_user     = "kibana_monitor";
my $opt_password = "ReadOnly00";
my $opt_testing  = 0;

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
	'p=s'			=> \$opt_port,
	'port=s'		=> \$opt_port,
	'U=s'			=> \$opt_user,
	'user=s'		=> \$opt_user,
	'P=s'			=> \$opt_password,
	'Password=s'		=> \$opt_password,
	) || print_help();

# If somebody wants the help ...
if ($opt_help) {
	print_help();
}

my $base_url = "http://$opt_user:$opt_password\@$opt_host:$opt_port";
my $fleet_url = "$base_url/api/fleet/agents?perPage=10000";
my $useragent = LWP::UserAgent->new;
$useragent->ssl_opts(
    SSL_verify_mode => SSL_VERIFY_NONE, 
    verify_hostname => 0
);
my $request = HTTP::Request->new('GET', $fleet_url);
my $response = $useragent->request($request);

if (!$response->is_success) {
	print "UNKNOWN - Could not connect to server (${base_url}) [", $response->status_line , "]\n";
	exit 3;
}

my $json_content = $response->content;
if (!defined($json_content)) {
	print "UNKNOWN - cannot access Elastic Fleet Server API\n";
	exit 3;
}

if ($opt_debug) {
	printf "%s\n", $json_content;
}

my $hash_content = JSON::decode_json($json_content);
if (!defined($hash_content)) {
	printf "UNKNOWN - cannot decode JSON string\n";
	exit 3;
}

my $hc = $hash_content->{list};
my @agents = @$hc;
my $size = @agents;
my $n = 0;
my $nprob = 0;
my $ntot = 0;
my $probstr = "";
my $verbstr = "";
my $hostname;
my $hoststatus;
my $hoststatusdate;
my $agentversion;

while($n < $size) {
	$hostname   = $agents[$n]->{"local_metadata"}->{"host"}->{"name"};
	$hoststatus = $agents[$n]->{"status"};
	$hoststatusdate = $agents[$n]->{"last_checkin"};
	$agentversion = $agents[$n]->{"agent"}->{"version"};
	if ($#opt_verbose > 1) {
		print "Host: $hostname:$hoststatus:$hoststatusdate:$agentversion\n";
	}
	if ($hoststatus !~ /online/) {
		$nprob++;
		$probstr.="$hostname -> $hoststatus ($hoststatusdate)\n";
	} else {
		$verbstr.="$hostname -> $hoststatus ($hoststatusdate)\n";
	}
	$ntot++;
	$n++;
}

if ($nprob > 0) {
	print "CRITICAL - $nprob Agent(s) are not 'online' | val=$nprob;0;1;0;$ntot\n";
	print "$probstr";
	if ($#opt_verbose) {
		print "$verbstr";
	}
	exit 2;
}

print "OK - $ntot Agent(s) are 'online' | val=$nprob;0;1;0;$ntot\n";
if ($#opt_verbose) {
	print "$verbstr";
}
exit 0;

# --------------------------------------------------- helper -----------------------------------------
#

sub print_help() {
	printf "%s, Version %s\n",$PROGNAME, $VERSION;
	print "Copyright (c) 2020 Juergen Vigna\n";
	print "This program is licensed under the terms of the\n";
	print "GNU General Public License\n(check source code for details)\n";
	print "\n";
	printf "Get status of Elastic Agents registered in Fleet Server\n";
	print "\n";
	print_usage();
	print "\n";
	print " -V (--version)   Programm version\n";
	print " -h (--help)      usage help\n";
	print " -v (--verbose)   verbose output\n";
	print " -D (--debug)     debug output\n";
	print " -H (--host)      Kibana Server hostname/ip (default: $opt_host)\n";
	print " -p (--host)      Kibana Server port (default: $opt_port)\n";
	print " -U (--user)      Kibana User (default: $opt_user)\n";
	print " -P (--password)  Kibana User Password (default: ***)\n";
	print "\n";
	exit 0;
}

sub print_usage() {
	print "Usage: \n";
	print "  $PROGNAME [-H|--host <hostname/ip>] [-p|--port <tcp-port>] [-U|--user <username>] [-P|--password <password>] [-T|--testonly]\n";
	print "  $PROGNAME [-h | --help]\n";
	print "  $PROGNAME [-V | --version]\n";
}
