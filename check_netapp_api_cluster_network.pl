#!/usr/bin/perl

# nagios: -epn
# --
# check_netapp_cluster_network - Check Network Ports of NetApp Cluster
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (GPL). If you
# did not receive this file, see http://www.gnu.org/licenses/gpl.txt.
#
# Author: Juergen Vigna <juergen.vigna@wuerth-phoenix.net>
# Date: 2025/01/13
# --


use strict;
use warnings;
use Getopt::Long;

use IO::Socket::SSL qw();
use LWP;
use JSON::XS;

use Try::Tiny;
use Data::Dumper;

sub json_from_call;

Getopt::Long::Configure('bundling');

GetOptions(
        'H|hostname=s' => \my $Hostname,
    	'u|username=s' => \my $Username,
    	'p|password=s' => \my $Password,
    	'w|warning=i'  => \my $Warning,
    	'c|critical=i' => \my $Critical,
    	'f|perf'       => \my $perf,
    	'e|exclude=s'  => \my $exclude,
    	'r|regexp'     => \my $regexp,
    	'v|verbose'    => \my $verbose,
    	'h|help'       => sub { exec perldoc => -F => $0 or die "Cannot execute perldoc: $!\n"; },
) or Error("$0: Error in command line arguments\n");

my $ua = LWP::UserAgent->new(
    ssl_opts => {
        'verify_hostname' => 0,
        'SSL_verify_mode' => IO::Socket::SSL::SSL_VERIFY_NONE,
    },
);

sub Error {
    print "$0: ".$_[0]."\n";
    exit 2;
}
Error( 'Option --hostname needed!' ) unless $Hostname;
Error( 'Option --username needed!' ) unless $Username;
Error( 'Option --password needed!' ) unless $Password;
#Error( 'Option --warning needed!' ) unless $Warning;
#Error( 'Option --critical needed!' ) unless $Critical;

my $json;

$json = json_from_call( "/network/ethernet/ports?fields=*" );

#print Data::Dumper::Dumper($json);

my $perfmsg = "";
my $errmsg = "";
my $warnmsg = "";
my $ports = $json->{'records'};
my $totports = 0;
my $downports = 0;
my $upports = 0;
my $exclports = 0;
my $verbout = "";

foreach my $port (sort { $a->{name} cmp $b->{name} } @$ports){
	my $port_name = $port->{node}->{name} . "-" . $port->{'name'};
	my $port_enabled = $port->{'enabled'};
	my $port_state = $port->{'state'};
	$totports++;

	if (defined($exclude)) {
		if (($regexp and ($port_name =~ m/$exclude/)) or ($port_name =~ m/^$exclude$/)) {
			$exclports++;
			if ($port_enabled || ($port_state =~ m/up/)) {
				$warnmsg .= " ${port_name}:${port_enabled}:${port_state}";
			}
			next;
		}
	}

	if ($verbose) {
		$verbout .= "${port_name}: ${port_enabled}:${port_state}\n";
	}
	if (!$port_enabled || ($port_state !~ m/up/)) {
		$downports++;
		$errmsg .= " ${port_name}:${port_enabled}:${port_state}";
	} else {
		$upports++;
	}
}

if ($perf) {
	$perfmsg = " ports=${totports} ports_up=${upports} ports_down=${downports} ports_exclude=${exclports}";
}

if ($downports > 0) {
	print "CRITICAL - $downports ports in DISABLED and/or DOWN status |$perfmsg\n";
	if ($warnmsg) { print "WARNING: " . $warnmsg . "\n"; }
	if ($verbose) { print $verbout; }
	exit 2;
}

if ($warnmsg) {
	print "WARNING - some excluded ports are not in DISABLED/DOWN, $warnmsg | $perfmsg\n";
	exit 1;
}

print "OK - ALL enabled ports are UP |$perfmsg\n";
if ($verbose) { print $verbout; }
exit 0;

sub json_from_call($) {

        my $url = shift;

        my $req = HTTP::Request->new( GET => "https://$Hostname/api$url" );
        $req->content_type( "application/json" );
        $req->authorization_basic( $Username, $Password );

        my $res = $ua->request( $req );
        die $res->status_line unless $res->is_success;

        my $result_decoded;
        my $decode_error = 0;
        try {
                $result_decoded = JSON::XS::decode_json( $res->content );
        }
        catch {
                $decode_error = 1;
        };

        die "Konnte JSON nicht dekodieren"  if  $decode_error;

        return $result_decoded;
}

__END__

=encoding utf8

=head1 NAME

check_netapp_api_cluster_disk_totals - Check Cluster real Space Usage

=head1 SYNOPSIS

check_netapp_api_cluster_disk_totals.pl -H HOSTNAME -u USERNAME
 -p PASSWORD -w PERCENT_WARNING [-v|--verbose]
 -c PERCENT_CRITICAL [--perf|-f] [-r|--regex] [--aggr|-A AGGR]

=head1 DESCRIPTION

Checks the Aggregates-Sum real Space Usage of the NetApp System and warns
if warning or critical Thresholds are reached

=head1 OPTIONS

=over 4

=item -H | --hostname FQDN

The Hostname of the NetApp to monitor (Cluster or Node MGMT)

=item -u | --username USERNAME

The Login Username of the NetApp to monitor

=item -p | --password PASSWORD

The Login Password of the NetApp to monitor

=item -w | --warning PERCENT_WARNING

The Warning threshold

=item -c | --critical PERCENT_CRITICAL

The Critical threshold

=item -f | --perf

Flag for performance data output

=item -A | --aggr

Check only specific aggregate

=item -e | --exclude

Optional: String for names of ports to exclude from check

=item -r | --regex

Optional: aggregate name is a regex

=item -h | --help

=item -?

to see this Documentation

=back

=head1 EXIT CODE

3 on Unknown Error
2 if Critical Threshold has been reached
1 if Warning Threshold has been reached
0 if everything is ok

=head1 AUTHORS

 Alexander Krogloth <git at krogloth.de>


