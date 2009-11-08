#!/usr/bin/perl -w

use strict;
use Getopt::Long;
use LWP::UserAgent;
use Time::HiRes;

my $ADDR = "localhost:80";
my $COUNT = 0;
my $SLEEP = 0;
GetOptions('a=s' => \$ADDR, 'c=i' => \$COUNT, 's=i' => \$SLEEP );
if ($ADDR eq '' || $COUNT < 1) {
    print STDERR << "EOF";
[usage]: $0 -a <address> -c <count> [-s <sleep>]
  -a       : request address
  -c       : request count
  -s       : sleep (millisecond)
EOF
    exit(1);
}
my $i=0;
while($i < $COUNT) {
    my $ua = new LWP::UserAgent;
    my $req = new HTTP::Request GET => "http://$ADDR";
    my $res = $ua->request($req);
    print $res->status_line . "\n";
    if (! $res->is_success) {
        print "fail to access $ADDR \n";
    }
    $i++;
    Time::HiRes::usleep($SLEEP*1000);
}
