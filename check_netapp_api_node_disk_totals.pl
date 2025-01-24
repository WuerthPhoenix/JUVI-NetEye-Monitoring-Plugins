#!/usr/bin/perl

# nagios: -epn
# --
# check_aggr - Check Aggregate real Space Usage
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (GPL). If you
# did not receive this file, see http://www.gnu.org/licenses/gpl.txt.
#
# Author: Juergen Vigna <juergen.vigna@wuerth-phoenix.net>
# Date: 2025/01/14
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
    	'A|aggr=s'     => \my $Aggr,
    	'f|perf'       => \my $perf,
    	'e|exclude=s'  => \my @excludelistarray,
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

my %Excludelist;
@Excludelist{@excludelistarray} = ();
my $excludeliststr = join "|", @excludelistarray;

sub Error {
    print "$0: ".$_[0]."\n";
    exit 2;
}
Error( 'Option --hostname needed!' ) unless $Hostname;
Error( 'Option --username needed!' ) unless $Username;
Error( 'Option --password needed!' ) unless $Password;
Error( 'Option --warning needed!' ) unless $Warning;
Error( 'Option --critical needed!' ) unless $Critical;

my $perfmsg = '';
my $critical = 0;
my $warning = 0;
my $ok = 0;
my $crit_msg;
my $warn_msg;
my $ok_msg;

my $json;

if($Aggr){
	$json = json_from_call( "/storage/aggregates?name=$Aggr&fields=space.block_storage.used,space.block_storage.size,space.block_storage.available,space.block_storage.physical_used_percent,space.efficiency_without_snapshots_flexclones.logical_used" );
} else {
	$json = json_from_call( "/storage/aggregates?fields=space.block_storage.used,space.block_storage.size,space.block_storage.available,space.block_storage.physical_used_percent,space.efficiency_without_snapshots_flexclones.logical_used" );
}

my $aggrs = $json->{'records'};
my $bytesused = 0;
my $logicalbytesused = 0;
my $bytesavail = 0;
my $bytestotal = 0;
my $totpercent = 0;

foreach my $aggr (sort { $a->{name} cmp $b->{name} } @$aggrs){

        my $aggr_name = $aggr->{'name'};

        # exclude root aggregates
        unless($aggr_name =~ m/^aggr0_/) {

            next if exists $Excludelist{$aggr_name};

            if ($regexp and $excludeliststr) {
                if ($aggr_name =~ m/.$excludeliststr/) {
                    next;
                }
            }

            my $space = $aggr->{'space'}->{'block_storage'};
            my $eff = $aggr->{'space'}->{'efficiency_without_snapshots_flexclones'};
            $bytesused  += $space->{'used'};
            $logicalbytesused  += $eff->{'logical_used'};
            $bytesavail += $space->{'available'};
            $bytestotal += $space->{'size'};
            my $percent += $space->{'physical_used_percent'};
            if ($verbose) {
		print "$aggr_name: $percent\n";
            }
        }
}

$totpercent = ($bytesused / $bytestotal) * 100;
if ($perf) {
	my $warn_bytes = $Warning*$bytestotal/100;
	my $crit_bytes = $Critical*$bytestotal/100;

	$perfmsg = " used=${bytesused}B;$warn_bytes;$crit_bytes;0;$bytestotal used%=${totpercent}% available=${bytesavail}B total=${bytestotal}B logicalused=${logicalbytesused}B";
}

if($totpercent >= $Critical) {
	print "CRITICAL: too much space used ($totpercent% > $Critical%)|$perfmsg\n";
	exit 2;
} elsif ($totpercent >= $Warning) {
	print "WARNING: too much space used ($totpercent% > $Warning%)|$perfmsg\n";
	exit 1;
} else {
	printf "OK: %.2f%% space used",$totpercent;
	print "|$perfmsg\n";
	exit 0;
}

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

Optional: The name of an aggregate that has to be excluded from the checks (multiple exclude item for multiple aggregates)

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


