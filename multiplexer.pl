#!/usr/bin/perl

# COPYRIGHT:
# This software is Copyright (c) 1996-2009 NETWAYS GmbH
# (Except where explicitly superseded by other copyright notices)
#
# LICENSE:
#
# This work is made available to you under the terms of Version 2 of
# the GNU General Public License. A copy of that license should have
# been provided with this software, but in any event can be snarfed
# from www.gnu.org.
#
# This work is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
# CONTRIBUTION SUBMISSION POLICY:
#
# (The following paragraph is not intended to limit the rights granted
# to you to modify and distribute this software under the terms of
# the GNU General Public License and is only of importance to you if
# you choose to contribute your changes and enhancements to the
# community by submitting them to NETWAYS GmbH.)
#
# By intentionally submitting any modifications, corrections or
# derivatives to this work, or any other work intended for use with
# this source, to NETWAYS GmbH, you confirm that you are
# the copyright holder for those contributions and you grant
# NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.

use strict;

use Data::Dumper;

use IO::Socket;
use IO::Handle;
use IO::Multiplex;

#use Net::Pcap;
use Net::Pcap::Reassemble;
#$Net::Pcap::Reassemble::debug = 1;

use Getopt::Long;
use File::Basename;

my $mux = new IO::Multiplex;

use vars qw(
  $opt_h

  $server_port
  $multiplex_port
  $data_port
  $interface

  $nameserver

  $opt_version

);

my $progname = basename($0);

# default values
$server_port = 2123;
$multiplex_port =2123;
$data_port = 2152;

Getopt::Long::Configure('bundling');
my $status = GetOptions(
	"h|help" => \$opt_h,

	"p=i" => \$server_port,
	"P=i" => \$multiplex_port,
	"I=s" => \$interface,

	"V" => \$opt_version
);

print_version() if ( defined($opt_version) );
print_help()    if ( defined($opt_h) );

# Create a listening socket
my $sock = new IO::Socket::INET(
	Proto     => 'tcp',
	LocalPort => $multiplex_port,
	Listen    => SOMAXCONN,
	Reuse     => 1
  )
  or die "socket: $@";

# create dummy udp socket for data transfer to circumvent icmp dest unreach
my $dummy_udp_dara = new IO::Socket::INET (
	Proto		=> 'udp',
	LocalPort	=> 2152,
) or die "dummy UDP socket: $@";

pipe( CHILD_RDR, PARENT_WTR );
PARENT_WTR->autoflush(1);

# We use the listen method instead of the add method.
$mux->listen( $sock);

$mux->add( \*CHILD_RDR );
#$mux->add( \*STDOUT );

$mux->set_callback_object(__PACKAGE__);

my $pid = fork();
if ( !defined $pid ) { die("Unable to fork") }

if ($pid) {

	#parent
	close(PARENT_WTR);
	
	#Die Loop
	$mux->loop;

	# wait till child has finished
	wait();

	close(CHILD_RDR);

	exit;
}

else {

	#child
	close(CHILD_RDR);

	# Child process will do actual sniffing.
	# First, create our packet capturing device
	my ($pcap_t) = create_pcap();

	unless ($pcap_t) {
		die("Unable to create pcap");
	}

	# Capture packets
	#if(Net::Pcap::loop( $pcap_t, -1, \&process_pkt, 0 )==-2) {
	if(Net::Pcap::Reassemble::loop( $pcap_t, -1, \&process_pkt, 0 )==-2) {
		print Net::Pcap::geterror($pcap_t);
	}

	Net::Pcap::close($pcap_t);

	close(PARENT_WTR);
	exit;

}

sub create_pcap {

	my $to_ms = 0;

	my $promisc = 1;       # We're only looking for packets destined to us,
	                       # so no need for promiscuous mode.
	my $snaplen = 65535;   # we want the full packets

	my $opt = 1;           # Sure, optimisation is good...
	my ( $err, $net, $mask, $dev, $filter_t );


	# first fragmented packet [initially] - don't need to catch it this way because it will match by port number too
	my $fragment_first = "((ip[6] & 0x20 != 0) && (ip[6:2] & 0x1fff = 0))";
	# more fragments [intervening]
	my $fragment_further = "((ip[6] & 0x20 != 0) && (ip[6:2] & 0x1fff != 0))";
	# and last fragment [terminal]
	my $fragment_last = "((ip[6] & 0x20 = 0) && (ip[6:2] & 0x1fff != 0))";

	my $filter = "(udp && (src port $server_port || src port $data_port || dst port $data_port)) || ($fragment_further || $fragment_last)";


	# Look up an appropriate device (eth0 usually)
	if ( $interface eq "" ) {
		$dev = Net::Pcap::lookupdev( \$err );
	}
	else {
		$dev = $interface;
	}
	$dev or die("Net::Pcap::lookupdev failed.  Error was $err");

	if ( ( Net::Pcap::lookupnet( $dev, \$net, \$mask, \$err ) ) == -1 ) {
		die("Net::Pcap::lookupnet failed.  Error was $err");
	}

	# Actually open up our descriptor
	my $pcap_t =
	  Net::Pcap::open_live( $dev, $snaplen, $promisc, $to_ms, \$err );
	$pcap_t || die("Can't create packet descriptor.  Error was $err");

	if ( Net::Pcap::compile( $pcap_t, \$filter_t, $filter, $opt, $net ) == -1 )
	{
		die("Unable to compile filter string '$filter'");
	}

	# Make sure our sniffer only captures those bytes we want in
	# our filter.
	Net::Pcap::setfilter( $pcap_t, $filter_t );

	# Return our pcap descriptor
	return $pcap_t;
}

sub process_pkt {
	my ( $user_data, $hdr, $pkt ) = @_;

	my ($src_ip)         = 26;    # start of the source IP in the packet
	my ($src_port)		 = 34;
	my ($dst_ip)         = 30;    # start of the dest IP in the packet
	my ($dst_port)		 = 36;
	my ($gtp_data_start) = 42;    # start of gtp in the packet
	my ($gtp_ext_start)  = 58;    # start of gtp extension in the packet

	# extract the source IP addr into dotted quad form.
	my ($source) = sprintf( "%d.%d.%d.%d",
		ord( substr( $pkt, $src_ip,     1 ) ),
		ord( substr( $pkt, $src_ip + 1, 1 ) ),
		ord( substr( $pkt, $src_ip + 2, 1 ) ),
		ord( substr( $pkt, $src_ip + 3, 1 ) ) );

	# extract the destination IP addr into dotted quad form.
	my ($destination) = sprintf( "%d.%d.%d.%d",
		ord( substr( $pkt, $dst_ip,     1 ) ),
		ord( substr( $pkt, $dst_ip + 1, 1 ) ),
		ord( substr( $pkt, $dst_ip + 2, 1 ) ),
		ord( substr( $pkt, $dst_ip + 3, 1 ) ) );

	my ($data) = substr( $pkt, $gtp_data_start );
	my $hex_data = $data;
 	$hex_data =~ s/(.|\n)/sprintf("%02x",ord $1)/eg;

	my $line = sprintf "%s\t%s\t%s\t%s\t%s\t\n",$source,unpack("n",substr($pkt, $src_port,2)),$destination,unpack("n",substr($pkt, $dst_port,2)),$hex_data;
	printf PARENT_WTR $line;
	PARENT_WTR->flush;
}

sub mux_input {
	my $package = shift;
	my $mux     = shift;
	my $fh      = shift;
	my $input   = shift;
		

	foreach my $c ( $mux->handles ) {
		# output only for tcp sockets 
		$mux->write($c, $$input) if ($c != \*CHILD_RDR && defined $c);
	}

	# Remove the input from the input buffer.
	$$input = '';

}

sub print_version {
	print <<EOV;
$progname Version: 0.0.2 
EOV

	exit();
}

sub print_help {

	print <<EOU;

$progname -H 
Options are:

    -I <string>          Interfacename 
    -p <integer>         TCP Port (optional / default: 2123)
    -P <integer>         TCP Port of the multiplex process (optional /default: 2123)
    
	
    -h, --help           display this help and exit
    -V, --version        output version information and exit
    
an expample: ./multiplexer.pl -I eth0 -p 2123

EOU

	exit();
}

