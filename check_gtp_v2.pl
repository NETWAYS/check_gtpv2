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
use POSIX;

use threads;

use IO::Socket;
use IO::Handle;

#use Net::Pcap;
#use Net::PcapUtils;
use Net::DNS;

use Getopt::Long;

use File::Basename;

use Data::Dumper;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);

use POSIX qw(SIGALRM);

use Net::RawIP;
#use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Gtp;

use vars qw(
  $opt_h

  $host
  $server_port
  $multiplex_port
  $interface
  $hexcode

  $msisdn
  $apn
  $imsi
  $gsn_address

  $peer_id
  $password

  $bak_source
  $bak_src_port
  $bak_destination
  $bak_dst_port

  $data_ip
  $data_teid
  $gtp_gsn_ip
  $gtp_data_port
  $gtp_data_port_local

  $gtp
  $tcp
  $tcp_fin
  $tcp_raw
  $tcp_raw_seq
  $tcp_raw_ack_seq

  $dl_timeout
  $dl_timeout_flag
  $dl_timeout_warning
  $dl_str
  $dl_dump
  $dl_write_file
  $dl_checklength
  $dl_showwarn
  $dl_showlength
  $dl_host
  $dl_ip
  $dl_port
  $dl_path
  $dl_local_port
  $dl_running
  $dl_state
  $dl_last_ack
  $dl_final_ack_num
  %dl_data
  @dl_data_keys
  $dl_http_header_length
  $dl_data_length
  $dl_warning
  $dl_checkfail
  $dl_stream
  $dl_content_length
  $dl_http_chunked
  $dl_not_found
  $dl_not_found_warning
  $dl_duration
  $dl_duration_last_time
  $dl_duration_real
  $dl_rate
  $dl_rate_real
  $dl_tcpip_size_total
  $dl_showrate
  $dl_showrate_real

  $dl_good_slices
  $dl_bad_slices
  %dl_expected_packets

  $opt_t
  $sleep
  $timeout
  @timeouts

  $nameserver

  $opt_version

  $sequence_number
  $teid_control_plane

  $step

  $debug

);

# default values
$server_port     = 2123;
$multiplex_port  = 2123;
$gtp_data_port   = 2152;
$timeout         = 3;
$dl_timeout      = 10;
$hexcode         = "";
$interface       = "";
$sleep           = 1;

$peer_id  = "";
$password = "";

my $perfdata = "";

srand(time());
$sequence_number = floor(rand(60000));;

################################################
# static values
################################################

my $flags = "\x32";
my $teid  = "\x00\x00\x00\x00";

my $n_pdu_number               = "\xff";
my $next_extension_header_type = "\x00";

my $routing_area_identity = "\x03\x62\xf2\x10\xff\xfe\xff";
my $recovery              = "\x0e\x23";
my $selection_mode        = "\x0f\xfc";

my $teid_data_i              = "\x10\x5e\xc0\x95\x1c";
my $nsapi                    = "\x14\x05";
my $charging_characteristics = "\x1a\x08\x00";

my $end_user_address = "\x80\x00\x02\xf1\x21";

my $protocol_configuration_options =
  "\x84\x00\x1d\x80\xc0\x23\x06\x01\x00\x00\x06\x00\x00";
my $protocol_configuration_options_prot_2 =
"\x80\x21\x10\x01\x02\x00\x10\x81\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00";

#my $quality_of_service = "\x87\x00\x04\x02\x23\x92\x1f";
my $quality_of_service = "\x87\x00\x0c\x03\x13\x93\x1f\x73\x96\x97\xf7\x74\xfa\xff\xff";

my $rat_type = "\x97\x00\x01\x01";

my $teardown_indicator = "\x13\xff";

################################################

# constant values
my $MAXLEN    = 20;
my $OK        = 0;
my $WARNING   = 1;
my $CRITICAL  = 2;
my $UNKNOWN   = 3;
my %EXITCODES = (
	"$OK"       => 'OK',
	"$WARNING"  => 'WARNING',
	"$CRITICAL" => 'CRITICAL',
	"$UNKNOWN"  => 'UNKNOWN'
);
my $DNS_RETRIES = 2;

my @STEPS = ( "DNS", "CPCQ", "CPCR", "DPCQ", "DPCR" );

my %times = ();

my $progname = basename($0);

my ( $sec, $usec ) = gettimeofday();

my $pid;

# unbuffered output
$| = 1;

Getopt::Long::Configure('bundling');
my $status = GetOptions(
	"h|help" => \$opt_h,

	"H=s" => \$host,
	"p=i" => \$server_port,
	"P=i" => \$multiplex_port,
	"I=s" => \$interface,
	"x=s" => \$hexcode,

	"U=s" => \$peer_id,
	"S=s" => \$password,

	"m=s" => \$msisdn,
	"a=s" => \$apn,
	"i=s" => \$imsi,
	"g=s" => \$gsn_address,

	"d=s" => \$dl_str,
	"dump-to-file=s" => \$dl_write_file,
	"dump-to-screen" => \$dl_dump,
	"dump-check"     => \$dl_checklength,
	"dump-warning"   => \$dl_showwarn,
	"dump-length"    => \$dl_showlength,
	"dump-rate"      => \$dl_showrate,
	"dump-rate-real" => \$dl_showrate_real,
	"dl-timeout=i"	 => \$dl_timeout,
	"dl-timeout-warning"	=> \$dl_timeout_warning,
	"dl-not-found-warning"	=> \$dl_not_found_warning,

	"t=s" => \$opt_t,
	"s=i" => \$sleep,

	"n=s" => \$nameserver,

	"V" => \$opt_version,

	"debug=i" => \$debug
);

# split timeouts;
if ( defined($opt_t) ) {
	@timeouts = split( ",", $opt_t );
}
else {
	@timeouts = ($timeout);
}

# fill missing timeouts with default value
if ( @timeouts < @STEPS ) {
	my $i;
	for ( $i = @timeouts ; $i < @STEPS ; $i++ ) {
		$timeouts[$i] = $timeout;
	}
}

$timeouts[0]--;
$timeouts[0] *= $DNS_RETRIES * ( ( $nameserver =~ tr/,// ) + 1 );

$timeouts[1] += $sleep;

print_version() if ( defined($opt_version) );
print_help()
  if ( !defined($apn)
	|| !defined($imsi)
	|| !defined($msisdn) );


prepareDLData();


#encode hexcode within strings
$apn     = encode_hexstrings($apn);
$hexcode = encode_hexstrings($hexcode);

# set step
$step = 0;

# set alarm to DNS Timeout
$SIG{'ALRM'} = \&my_alarm;
alarm( ( $timeouts[$step] * ( ( $nameserver =~ tr /,// ) + 1 ) ) );

# resolv ggsn ips from apn
my $ggsn = $apn;
my @ggsnips;

stopwatch( \$sec, \$usec );

#host not defined? get ggsn-ips from apn
if ( !defined($host) ) {

	@ggsnips =
	  resolve_name( $ggsn, $nameserver, $timeouts[$step], $DNS_RETRIES );
}
else {
	@ggsnips = ($host);
}

$apn =~ s/\.[^.]*\.[^.]*\.[^.]*$//;

# if gsn_address is not set fetch interface's ip address
if ( !defined($gsn_address) ) {
	my $dummy = `/sbin/ifconfig $interface | grep "inet a" -i `;
	if ( $dummy =~ m/:(\d+\.\d+\.\d+\.\d+)/ ) {
		$gsn_address = $1 . "," . $1;
	}
}
else {
	if ( $gsn_address !~ m/,/ ) {
		$gsn_address .= "," . $gsn_address;
	}
}

#not finished! use first ip meanwhile
$host = shift @ggsnips;

#dns finished -> start stopwatch again.
stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );

# reset Alarmhandler for parent process
alarm $timeouts[$step];
$SIG{ALRM} = \&my_alarm;

my $write_sock;
$write_sock = IO::Socket::INET->new(
	Proto    => "udp",
	PeerPort => $server_port,
	PeerAddr => $host,
  )
  or my_exit("cannot open write socket: $@");

# send first paket out
udp_send(
	"create",     $host,    $server_port,
	$apn,         $msisdn,  $imsi,
	$gsn_address, $hexcode, $sequence_number++
);

#paket sent -> start stopwatch again
#stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );
#$step++;

my $sniffer = IO::Socket::INET->new(
	Proto    => "tcp",
	PeerAddr => "localhost",
	PeerPort => $multiplex_port,
  )
  or my_exit("cannot connect to multiplex process at localhost");

while (<$sniffer>) {
	process_pkt($_);
}

close($sniffer);

my_exit("Multiplexer stopped.");




#############################
# DL subs
#############################

sub prepareDLData {

	# init shared and global ariables
	$dl_running = 0;
	$dl_state = 0;
	$dl_warning = 0;
	$dl_timeout_flag = 0;
	$dl_not_found = 0;

	if (defined($dl_str)) {

		# extract download-target data from command-line parameter
		$dl_str =~ /^([^\|]+)\|(\d+\.\d+\.\d+\.\d+)\|(\d+)\|(.*)$/;
		my_exit('Invalid download source!') if (!defined($3) || !defined($2) || !defined($3) || ! defined($4));
		$dl_host = $1;
		$dl_ip = $2;
		$dl_port = $3;
		$dl_path = $4;

		# init for insertion of DTX into process plan
		my $last_step = @STEPS - 1;
		my $pos = 0;

		# search STEPS for right position to insert DTX
		foreach my $current (@STEPS) {
			last if ($current eq 'CPCR');
			$pos++;
		}

		my $pos_next = $pos + 1;
		
		@STEPS = (@STEPS[0 .. $pos], 'DTX', @STEPS[$pos_next .. $last_step]);
		@timeouts = (@timeouts[0 .. $pos], $dl_timeout, @timeouts[$pos_next .. $last_step]);

		# get a random download port out of the range 20000:60000
		srand(time());
		$dl_local_port = floor(rand(40000)) + 20000;
		$gtp_data_port_local = floor(rand(40000)) + 20000;


		# init flags and values
		$dl_http_chunked = 0;
		$dl_duration = 0;
		$dl_duration_last_time = 0;
		$dl_duration_real = 0;
		$dl_rate = 0;
		$dl_rate_real = 0;
		$dl_str = 1;
		$dl_tcpip_size_total = 0;

		# enable checking if warning is set
		$dl_checklength = 1 if (defined($dl_showwarn) || defined($dl_showlength));

	} else {

		# unset download flag and disable data dumping
		$dl_str = 0;
		$dl_dump = 0;
		$dl_write_file = 0;
		$dl_checklength = 0;
		$dl_showwarn = 0;
		$dl_showlength = 0;
		$dl_checkfail = 0;
		$dl_timeout_warning = 0;
		$dl_showrate = 0;

	}

}




sub prepareAndStartDownload {

	my ($data) = @_;

	$gtp_gsn_ip = gtpExtractGSNIP($data);
	dbg('GSN-Data IP: ' . $gtp_gsn_ip, 1, 2);

	$data_ip = gtpExtractNewIP($data);
	dbg('Assigned TCP/IP Address: ' . $data_ip, 1, 2);

	$data_teid = gtpExtractDataTeid($data);
	dbg('Assigned Data TEID: ' . $data_teid, 1, 2);

	$write_sock = IO::Socket::INET->new(
		Proto    => 'udp',
		PeerPort => $gtp_data_port,
		PeerAddr => $gtp_gsn_ip,
		LocalPort => $gtp_data_port_local,
	) or my_exit("cannot open write socket: $@");

	$gtp = Gtp->new();

	$tcp_fin = 0;
	$dl_running = 1;
	$dl_state = 0;

	processDownload();

}




sub processDownload {

	# stop time measure
	getTimeDiff(0);

	# get udp payload
	my ($udp_payload) = @_;

	# init
	my $ip;
	my $tcp;
	my $gtp = Gtp->new();
	my $send = 1;
	my $current_length = 0;
	my $tmp_seq_num = 0;
	my $tmp_ack_num = 0;

	my $tcp_raw = Net::RawIP->new({
		ip  => {
			saddr	=> $data_ip,
			daddr	=> $dl_ip,
		},
		tcp => {
			source	=> $dl_local_port,
			dest	=> $dl_port,
		},
	});


	# unwrap IP and TCP data
	if ($dl_state) {

		$gtp->{packet} = $udp_payload;
		$gtp->getdata();
		$ip = NetPacket::IP->decode($gtp->{data});
		$tcp = NetPacket::TCP->decode($ip->{data});

		# extract sequence number and acknowledge number from TCP header
		$tmp_seq_num = unpack("N", substr($ip->{data}, 4, 4));
		$tmp_ack_num = unpack("N", substr($ip->{data}, 8, 4));

		# verify checksum and prepare for retransmission if checksum is incorrect
		if (!verifyTCPChecksum($ip, $tcp)) {

			dbg('invalid checksum found!', 1, 3);

			# set download state to 'invalid'
			$dl_state *= -1;
			$send = 0;

		}

		$dl_tcpip_size_total += length($udp_payload);

	}


	# process incoming data and prepare packets for answers
	if ($dl_state == 0) {

		# send syn
		dbg('DTX: SYN');

		$tcp_raw->set({
			tcp => {
				syn => 1,
				seq => 0,
			},
		});

		$dl_state++;

		$dl_duration_real = [gettimeofday()];

	} elsif ($dl_state == 1) {

		# send ack
		dbg('DTX: ACK');

		# store ack and seq for GET request
		$tcp_raw_seq = $tcp->{acknum};
		$tcp_raw_ack_seq = $tcp->{seqnum} + 1;

		$tcp_raw->set({
			tcp => {
				ack => 1,
				ack_seq => $tcp_raw_ack_seq,
				seq => $tcp_raw_seq,
			},
		});

		$dl_state++;

	} elsif ($dl_state == 3) {

		# retrieve data and begin to store when matching header has been found
		dbg('DTX: wait for content and begin download');

		# begin to store data
		if ($tcp->{data} =~ /HTTP\/\d\.\d 200 OK/i) {

			$tcp->{data} =~ /^(.*\r\n\r\n)(.*)$/s;

			if (defined($1) && defined($2)) {

				my $http_header = $1;
				my $http_content = $2;

				if ($http_header =~ /Content-Length:\s+(\d+)/si) {
					$dl_content_length = $1;
					dbg('DTX: http_header Content-Length: ' . $dl_content_length, 1, 3);
				} else {
					$dl_content_length = "n/a";
				}

				my $chunk_head_length = 0;

				# check for chunked encoding
				if ($http_header =~ /Transfer-Encoding: chunked\r\n/si) {

					# chunked it is. get length of chuck-data and strip off chunk from html-content
					$http_content =~ s/^([^;\r\n]+)(;[^\r\n]+)*\r\n(.*)$/$3/s;
					$dl_http_chunked = hex($1) if (defined($1));

					dbg('DTX: chunked encoding. length: ' . $dl_http_chunked, 1, 3);

					# get length of chunk defs
					$chunk_head_length += length($1) if (defined($1));
					$chunk_head_length += length($2) if (defined($2));
					$chunk_head_length += 2 if (defined($3));

				}

				# get total length of non-content
				$dl_http_header_length = length($http_header) + $chunk_head_length;

				$dl_data{$tmp_seq_num} = $http_content;
				$dl_last_ack = $tcp->{acknum};
				$dl_state++;

				dbg('DTX: download file');
				$dl_good_slices = 0;
				$dl_bad_slices = 0;
			}

		} elsif ($tcp->{data} =~ /HTTP\/1.1 404 Not Found/i) {

			$dl_not_found = 1;
			$dl_state = 0;
			$dl_running = 0;

		}

		$send = 0;

	} elsif ($dl_state == 4) {

		# retrieve and store data
		dbg('DTX: download file, got seq num ' . $tmp_seq_num . '.', 1, 4);

		# set fin indicator if server is about to end transmission
		if ($tcp->{flags} & FIN) {
			$tcp_fin = 1;
			dbg('DTX: FIN received at seq num: ' . $tmp_seq_num, 1, 4);
		}

		# store data if we expect this paket and it is not empty
		if ((exists $dl_expected_packets{$tmp_seq_num}) || ($dl_good_slices == 0)) {
			# store data if it is not an empty packet
			if ($tcp->{data} ne '') {
				$dl_data{$tmp_seq_num} = $tcp->{data};
				$current_length = length($tcp->{data});
				$dl_good_slices++;
				delete $dl_expected_packets{$tmp_seq_num};
			}
		} else { 
			$dl_bad_slices++;

			# get and sort hash keys
			my @seq_num_keys = sort(keys(%dl_expected_packets));
			my $expected_packets = '';

			foreach my $current (@seq_num_keys) {
				if ($expected_packets != '') { $expected_packets .= ', '}
				$expected_packets .= $dl_expected_packets{$current} if ($current);
			}

			dbg('DTX: packets out of sync received: ' . $dl_bad_slices . ' got seq num: ' . $tmp_seq_num . ' but expect: ' . $expected_packets, 1, 4);
		}

		if ($current_length || $tcp_fin) {

			# store next ACK as final ACK
			$dl_final_ack_num = $tmp_seq_num + $current_length;

			$tcp_raw->set({
				tcp => {
					ack => 1,
					fin => $tcp_fin,
					seq => $tmp_ack_num,
					ack_seq => $dl_final_ack_num + $tcp_fin,
				},
			});

			$dl_last_ack = $tcp->{acknum};

		} else {

			# do not send if received TCP packet contained no payload
			$send = 0;

		}

	}

	dbg('DTX: got packet with seq num ' . $tmp_seq_num . '.', 1, 4);

	# send acks
	if ($send) {

		# encapsulate TCP/IP packet in GTP packet and send via UDP
		my $gtp_packet = createGTPPacket($tcp_raw->packet());
		$write_sock->send($gtp_packet);
		$write_sock->flush;
		dbg('ACK: send on packet with seq num ' . $tmp_seq_num . '.', 1, 4);

	}

	# memorize the seqnumbers we are awaiting
	$dl_expected_packets{$dl_final_ack_num + $tcp_fin} = $tmp_seq_num;

	# send additional GET request if ACK state has just passed
	if ($dl_state == 2) {

		# send get request
		dbg('DTX: GET');

		# get HTTP-request string
		my $get_request = createHTTPGETRequest();

		# assemble packet, wrap it up and send it
		$tcp_raw->set({
			tcp => {
				psh => 1,
				ack => 1,
				ack_seq => $tcp_raw_ack_seq,
				seq => $tcp_raw_seq,
				data	=> $get_request,
			},
		});

		$dl_state++;

		my $gtp_packet = createGTPPacket($tcp_raw->packet());
		$write_sock->send($gtp_packet);
		$write_sock->flush;

	}


	# reset flags and check received data if transfer is completed
	if ($tcp_fin) {

		# unset download flag and counter
		$dl_state = 0;
		$dl_running = 0;

		$dl_duration_real = tv_interval($dl_duration_real);
		$dl_rate_real = getMBitPerSec($dl_tcpip_size_total, $dl_duration_real);
		$dl_rate = getMBitPerSec($dl_tcpip_size_total, $dl_duration, 1);
		dbg('DTX: size: ' . $dl_tcpip_size_total . 'b, duration: ' . $dl_duration . 's, rate: ' . $dl_rate . 'MBit/s');

	}


	# recover download state if it was set to 'invalid checksum'
	$dl_state *= -1 if ($dl_state < 0);

	# start time measure
	getTimeDiff();

}




#
# createGTPPacket - creates a gtp packet for data transfer
#
# @param	string		$data		payload of GTP packet
# @return	GTP						GTP packet
#
sub createGTPPacket {

	my $data = shift;

	# create new GTP object
	my $gtp = Gtp->new();

	# set default values
	$gtp->set({
		'header' => {
			'version'			=> 1,
			'protocol_type'			=> 1,
			'spare_bit'			=> 0,
			'extension_header_flag'		=> 0,
			'sequence_number_flag'		=> 0,
			'n_pdu_number_flag'		=> 0,
			'message_type'			=> 255,
			'teid'				=> $data_teid,
			'sequence_number'		=> 1,
			'n_pdu_number'			=> 255,
			'next_extension_header_type'	=> 0,
		},
		'data' => $data,
	});

	$gtp->{'header'}->{'length'} = 24 + length($data);

	return $gtp->packet();

}




#
# gtpExtractGSNIP - extracts GSN IP for data transfer from GTP responde
#
# @param	string		$data		udp payload of response
# @return	string					extracted IP
#
sub gtpExtractGSNIP {

	my ($payload) = @_;

	# set prefix
	my $ip_prefix = "\x85\x00\x04";

	# extract GSN IP and create string
	$payload =~ /$ip_prefix....$ip_prefix(....)/;
	my $ip = $1;

	my @ip_arr = split('', $ip);
	my $ip_str = sprintf(
		'%i.%i.%i.%i',
		ord($ip_arr[0]),
		ord($ip_arr[1]),
		ord($ip_arr[2]),
		ord($ip_arr[3])
	);

	# return created string
	return $ip_str;

}




#
# gtpExtractNewIP -  extracts the new IP from GTP response
#
# @param	string		$data		udp payload of response
# @return	string					extracted IP
#
sub gtpExtractNewIP {

	# get parameters (UDP payload)
	my ($payload) = @_;

	# set prefix
	my $ip_prefix = "\x80\x00\x06\xf1\x21";

	# extract IP and create string
	$payload =~ /$ip_prefix(....)/s;
	my $ip = $1;

	my @ip_arr = split('', $ip);
	my $ip_str = sprintf(
		'%i.%i.%i.%i',
		ord($ip_arr[0]),
		ord($ip_arr[1]),
		ord($ip_arr[2]),
		ord($ip_arr[3])
	);

	# return created string
	return $ip_str;

}




#
# gtpExtractDataTeid - extracts the new Data TEID from GTP response
#
# @param	string		$data		udp payload of response
# @return	string					extracted TEID
#
sub gtpExtractDataTeid {

	# get parameters (UDP payload)
	my ($payload) = @_;

	# extract and convert data teid
	my $teid = 0;
	my $exp = 3;
	for (my $x = 19; $x < 23; $x++) {
		$teid += ord(substr($payload, $x, 1)) * (256**$exp);
		$exp--;
	}

	# return created string
	return $teid;

}




#
# createHTTPGETRequest - creates the HTTP header for the GET request
#
# @param	none
# @return	string				HTTP header code
#
sub createHTTPGETRequest {

	# create request and return it
	my $request = sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14\r\nAccept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nConnection: close\r\n\r\n",
		$dl_path,
		$dl_host
	);

	return $request;

}




#
# verifyTCPChecksum - verifies tcp checksums
#
# @param	ref		$ip		reference to a NetPacket::IP object
# @param	ref		$tcp		reference to a NETPacket::TCP object
# @return	integer				1 on valid checksum else 0
#
sub verifyTCPChecksum {

	my ($ip, $tcp) = @_;

	# get current checksum
	my $received = $tcp->{cksum};

	# delete old checksum
	$tcp->{cksum} = 0;

	# reassemble packets
	$ip->{data} = $tcp->encode($ip);
	my $packet = $ip->encode();

	# redecode packet
	$ip = NetPacket::IP->decode($packet);
	$tcp = NetPacket::TCP->decode($ip->{data});

	dbg("TCPchksum: $received chksum: " . $tcp->{cksum} . ", length: " . length($tcp->{data}) . ", content: \n" . $tcp->{data}, 1, 4) if ($dl_dump);

	# compare checksums and return 1 if the match
	return 1 if ($received == $tcp->{cksum});

	# checksums did not match -> return 0
	return 0;

}




################################
# helper - subs
################################

#
# assembleDLData - generates a complete stream of downloaded data and checks integrity by differences in data length
#
# @param	none
# @return	string				stream
#
sub assembleDLData {

	# init
	my $stream = '';
	my $dl_ack_diff = 0;
	my $dl_chunked_footer_length = 0;

	# get and sort hash keys
	@dl_data_keys = sort(keys(%dl_data));

	# assemble packets to one stream
	foreach my $current (@dl_data_keys) {
		$stream .= $dl_data{$current} if ($dl_data{$current});
	}

	my $stream_length = length($stream);

	# strip off chunk footer if there is any
	if ($dl_http_chunked) {

		$stream = substr($stream, 0, $dl_http_chunked);
		$dl_chunked_footer_length = $stream_length - $dl_http_chunked;
		$stream_length = $dl_http_chunked;

	}

	# store length and check integrity
	$dl_data_length = $stream_length + $dl_http_header_length + $dl_chunked_footer_length;
	
	if ($dl_checklength) {
		$dl_ack_diff = $dl_final_ack_num - $dl_data_keys[0];
		dbg('check length of raw data: ' . $dl_ack_diff . ' == expected length: ' . $dl_data_length . ' ?', 1, 3);
		dbg('check content length: ' . $stream_length . ' == expected length: ' . $dl_content_length . ' ?', 1, 3);
		dbg('I\'ve got: good slices: ' . $dl_good_slices . ' bad slices: ' . $dl_bad_slices, 1, 3);
	}

#	if ($dl_data_length != $dl_content_length) {
	if ($dl_data_length != $dl_ack_diff) {
		$dl_checkfail = 1 if ($dl_showlength);
		$dl_warning = 1 if ($dl_showwarn);
	}

	# return stream
	return $stream;

}




#
# storeDataInFile - stores downloaded data in a dump file
#
# @param	none
# @return	none
#
sub storeDataInFile {

	# extract filename and path from download path
	$dl_path =~ /^\/([.]*)([^\/]+)$/;
	my $file_path = $1;
	my $file_name = $2;

	# substitute dots in progname
	my $prog_name = $progname;
	$prog_name =~ s/(\.)/_/g;

	# create date-and-time string
	my ($sec, $min, $hour, $day, $month, $year) = (localtime(time()))[0,1,2,3,4,5,6];
	$year += 1900;
	$month++;
	if ($month > 12) {
		$month = 1;
		$year++;
	}
	my $date = sprintf("%4i%02i%02i%02i%02i%02i", $year, $month, $day, $hour, $min, $sec);

	# generate name for dump file without name of downloaded file and clean a little
	my $dumpfile = sprintf("-%s-%s-%s-%s", $date, $data_ip, $dl_host, $file_path);
	$dumpfile =~ s/([\.\/])/_/g;

	# clean path and append '/' to path, if not set
	$dl_write_file =~ s/^\s+|\s+$//g;
	$dl_write_file .= '/' if ($dl_write_file ne '' && substr($dl_write_file, -1) ne '/');

	# finally, put it all together
	$dumpfile = $dl_write_file . $prog_name . $dumpfile . $file_name;

	dbg('dumping to file \'' . $dumpfile . '\'', 1, 3);

	# dump data to file
	open(DUMPFILE, "> $dumpfile");
	print DUMPFILE $dl_stream;
	close(DUMPFILE);

}




#
# hexdump - dumps data in hex-editor style
#
# @param	string		$dump_data	data to dump
# @ return	none
#
sub hexdump {
	my $hexdump_ascii = '';
	my $dump_data = shift;
	my @hex_arr = unpack('(H2)*', $dump_data);
	my @chr_arr = map({($_ ge ' ' && $_ le '~') ? $_ : '.'} split('', $dump_data));
	my $max = length($dump_data) - 1;
	my $hex = '';
	my $chr = '';
	my $newline = 0;
	for (my $x = 0; $x <= $max; $x+=8) {
		my $last = $x + 7;
		$last = $max if ($last > $max);
		$hex .= join(' ', @hex_arr[$x .. $last]);
		$chr .= join('', @chr_arr[$x .. $last]);
		if ($newline) {
			print $hex . '    ' . $chr . "\n";
			$hex = '';
			$chr = '';
			$newline = 0;
		} else {
			$hex .= '  ';
			$chr .= ' ';
			$newline = 1;
		}
	}
	my $len_hex = length($hex);
	if ($len_hex) {
		my $space = 53 - $len_hex;
		print $hex . ' 'x$space . $chr . "\n";
	}
}




#
# dbg - creates debugging output
#
# @param	mixed		$data		data to output
# @param	integer		$mode		debugging mode for code generation
# @param	integer		$level		debugging level
# @return	none
#
sub dbg {

	if (defined($debug) && $debug) {

		my ($data, $mode, $level) = @_;

		$level = 1 if (!defined($level));

		if ($level <= $debug) {

			$mode = 1 if (!defined($mode));
			my $prefix = 'DEBUG_' . $level;

			if ($mode == 1) {
				print $prefix . ': ' . $data . "\n";
			} elsif ($mode == 2) {
				print $prefix . ' (dump): '. Dumper($data) if ($mode == 2);
			} elsif ($mode == 3) {
				print $prefix . ' (stream): ' . "\n";
				hexdump($data);
			}

		}

	}

}




#
# getTimeDiff - returns time difference between two calls of this function and returns it
#
# @param	integer		$mode		toggling of time measure
# @return	none
#
sub getTimeDiff {

	my ($mode) = @_;

	my $now = gettimeofday();

	if (defined($mode)) {
		$dl_duration_last_time = $now;
	} else {
		$dl_duration += ($now - $dl_duration_last_time);
	}

}




#
# getTimeDiffReal - returns time difference between two calls of this function and returns it
#
# @param	float		$time		if set: time to calculate difference from
# @return	float				time difference
#
sub getTimeDiffReal {

	my ($time) = @_;
	my $diff = gettimeofday();
	$diff -= $time if (defined($time));
	return $diff;

}




#
# getMBitPerSec - calculates MBit/s from size and duration
#
# @param	integer		$size		size in bytes
# @param	float		$duration	duration of data transfer
# @param	integer		$use_factor	if set, a factor recalc will be triggered
# @return	float				calculated MBit/s
#
sub getMBitPerSec {

	my ($size, $duration, $use_factor) = @_;
	my $mbit_per_sec = ($size * 8) / (1048576 * $duration);
	$mbit_per_sec *= 2.2 if (defined($use_factor));	# this factor is used to correct losses due to string processing
	return $mbit_per_sec;

}




#############################
# subs
#############################

sub udp_send {

	my ( $state, $host, $server_port, $apn, $msisdn, $imsi, $gsn_address ) = @_;

	my $data = "";

	my $head .= $flags;

	if ( $state eq "create" ) {

		# create
		$head .= "\x10";
	}
	else {

		# delete
		$head .= "\x14";
	}

	$data .= $teid;

	#Sequence number
	$data .= pack( "n", $sequence_number );

	$data .= $n_pdu_number;
	$data .= $next_extension_header_type;

	if ( $state eq "create" ) {

		#imsi
		$data .= "\x02" . encode_numbers($imsi);

		$data .= $routing_area_identity;
		$data .= $recovery;
		$data .= $selection_mode;
		$data .= $teid_data_i;

		#TEID Control Plane
		$teid_control_plane = "\x11" . pack( "L", $$ );
		$data .= $teid_control_plane;

		$data .= $nsapi;
		$data .= $charging_characteristics;
		$data .= $end_user_address;

		#Access Point Name
		$apn = encode_apn($apn);
		$data .= "\x83" . pack( "n", length($apn) ) . $apn;

		# Authentication
		#		$data .= $protocol_configuration_options;

		$data .= protocol_configuration_options( $peer_id, $password );

		# GSN Address
		my @gsn_addresses = split( /,/, $gsn_address );
		my $i = 0;
		for ( ; $i < @gsn_addresses ; $i++ ) {
			$data .= "\x85\x00\x04" . inet_aton( $gsn_addresses[$i] );
		}

		#MSISDN
		$msisdn = encode_numbers($msisdn);
		$data .= "\x86" . pack( "n", length($msisdn) ) . $msisdn;

		$data .= $quality_of_service;
		$data .= $rat_type;

		$data .= $hexcode if ( defined($hexcode) );

	}
	else {
		$data .= $teardown_indicator;
		$data .= $nsapi;
	}

	$write_sock->send( $head . pack( "n", length($data) - 4 ) . $data )
	  or my_exit("cannot send: $!");
	$write_sock->flush;

}




sub encode_hexstrings {
	my ($hexstring) = @_;
	$hexstring =~ s/\/x([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/eg;
	return $hexstring;
}




sub encode_apn {
	my $rw    = "";
	my $i     = 0;
	my ($apn) = @_;
	my @parts = split( /\./, $apn );

	for ( $i = 0 ; $i < @parts ; $i++ ) {
		$rw .= pack( "C", length( @parts[$i] ) ) . $parts[$i];
	}
	return $rw;
}




sub resolve_name {
	my ( $hostname, $nameserver, $timeout, $retries ) = @_;
	my $res = Net::DNS::Resolver->new;

	my @nameservers = split( /,/, $nameserver );
	my @ips;

	my $last = 0;

	if ( $nameserver eq "" ) {
		@nameservers = $res->nameservers();
	}

	foreach my $ns (@nameservers) {
		for ( my $i = 0 ; $i < $retries ; $i++ ) {
			$res->tcp_timeout( $timeout / $retries / @nameservers );
			$res->udp_timeout( $timeout / $retries / @nameservers );

			$res->nameserver($ns);

			my $query = $res->send($hostname);

			if ($query) {
				foreach my $rr ( $query->answer ) {
					next unless $rr->type eq "A";
					push( @ips, $rr->address );
				}
				$last = 1;
				last;
			}
			last if ($last);
		}
	}

	if ( @ips == 0 ) {
		my_exit( "Cannot resolve APN: $hostname on DNS: $nameserver.",
			$CRITICAL );
	}

	return @ips;
}




sub protocol_configuration_options {

	my ( $peer_id, $password ) = @_;

	my $data =
	    pack( "C", length($peer_id) ) . $peer_id
	  . pack( "C", length($password) )
	  . $password;

	$data = "\x01\x00" . pack( "n", length($data) + 4 ) . $data;

	$data =
	    "\x80\xc0\x23"
	  . pack( "C", length($data) )
	  . $data
	  . $protocol_configuration_options_prot_2;

	$data = "\x84" . pack( "n", length($data) ) . $data;

	return $data;
}




sub encode_numbers {

	my ($msisdn) = @_;

	#MSISDN
	my $i;
	my $rw = "";

	my $international = 0;

	if ( $msisdn =~ m/\+/ ) {
		$international = 1;
		$msisdn =~ s/\+//;
	}

	my @digits = unpack( "c*", $msisdn );
	for ( $i = 0 ; $i < @digits ; $i++ ) {
		$digits[$i] -= ord("0");
	}
	for ( $i = 0 ; $i < @digits ; $i += 2 ) {
		my $first_digit;
		my $second_digit = 15;
		$first_digit = $digits[$i];
		if ( $i + 1 < @digits ) {
			$second_digit = $digits[ $i + 1 ];
		}
		else {
			$second_digit = 15;
		}
		$rw .= pack( "c", $second_digit * 16 + $first_digit );
	}

	$rw = "\x91" . $rw if ($international);
	return $rw;
}




# Routine to process the packet
sub process_pkt {
	my ($pkt) = @_;

	my ( $source, $src_port, $destination, $dst_port, $data, @anotherpacket ) = split( /\t/, $pkt );
	chomp($data);
	$data =~ s/([a-fA-F0-9]{2})/chr(hex $1)/eg;

	my $check_port = $write_sock->sockport();

	if (( $destination eq $host || $destination eq $gtp_gsn_ip ) or ( $source eq $host || $source eq $gtp_gsn_ip ))
	{
		dbg("PKT - source: $source, rc_port: $src_port, destination: $destination, dst_port: $dst_port, #data: " . length($data) . ".", 1, 4);
	}

	# Create response angekommen?
	if (    $source
		and $destination
		and $data
		and ( $source eq $host || $source eq $gtp_gsn_ip )
		and ( $check_port == $dst_port || $check_port == $gtp_data_port || $check_port == $gtp_data_port_local ) )
	{

		dbg('current step: ' . $STEPS[$step] . '. download active: ' . $dl_running, 1, 4);

		if ($STEPS[$step] eq 'DPCR') {

			# delete response angekommen?
			my ( $lsec, $lusec ) = gettimeofday();

			my $time =
			  'time_in_s=' . ( $lsec - $sec ) + ( $lusec - $usec ) / 1000000;
			$time .=
			  ' time_in_ms=' . ( $lsec - $sec ) * 1000000 + ( $lusec - $usec );

			# got response -> start stopwatch again
			stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );

			# Returncode ermitteln und gegebenenfalls abbrechen
			my $rc = unpack( "C", substr( $data, 13, 1 ) );

			if ( $rc != 128 ) {

				my_exit(
					$STEPS[$step]
					  . ' did not work on '
					  . $host
					  . ". Returncode: "
					  . $rc,
					$CRITICAL
				);

			} else {

				my_exit( 'APN is working on GGSN: ' . $host, $OK );

			}

		}

		if  ($STEPS[$step] eq 'DTX') {

			if ($dl_running) {

				# data download
				processDownload($data);

			} else {

				if (!$dl_timeout_flag && !$dl_not_found) {

					# create data stream and check integrity of download
					$dl_stream = assembleDLData();

					# mark invalid content by using a '!' and append content length to check output
					my $step_data = '';
					$step_data .= '!' if ($dl_checkfail);
					$step_data .= $dl_data_length if ($dl_showlength);
					$step_data .= '-' if ($dl_showlength && $dl_showrate);
					$step_data .= sprintf("%.2fMBit/s", $dl_rate) if ($dl_showrate);
					if ($dl_showrate_real) {
						$step_data .= ',' if ($dl_showrate);
						$step_data .= sprintf("%.2fMBit/s", $dl_rate_real);
						#$step_data .= ')' if ($dl_showrate);
					}
					$step_data = '(' . $step_data .  ')' if ($dl_showlength || $dl_showrate || $dl_showrate_real);
					$STEPS[$step] .= $step_data;

				} elsif($dl_timeout_flag) {

					dbg('DTX: timeout ' . $dl_timeout, 1, 5);
					$dl_stream = '';

				} elsif($dl_not_found) {

					dbg('DTX: 404 not found', 1, 5);
					$dl_stream = '';

				}

				# DPCQ
				stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );

			}

		}

		if ($STEPS[$step] eq 'CPCQ') {

			$bak_source = $source;
			$bak_src_port = $src_port;
			$bak_destination = $destination;
			$bak_dst_port = $dst_port;

			sleep($sleep);

			#got response-> start stopwatch again

			stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );
			# dies ist die Stelle an dem der delete request erzeugt werden muss
			# danach muss der entsprechende Return code zurueck

			# Returncode ermitteln und gegebenenfalls abbrechen
			my $rc = unpack( "C", substr( $data, 13, 1 ) );
			if ( $rc != 128 ) {
				my_exit(
					$STEPS[1]
					  . ' did not work on '
					  . $host
					  . ". Returncode: "
					  . $rc,
					$CRITICAL
				);
			}

			# neue Destination Address ermitteln

			# Positon ermitteln
			my $pos = 33;
			while (unpack("C",substr($data,$pos,1)) != 133) {
				$pos += unpack("n",substr($data,$pos+1,2))+2+1; 
			}
			my $new_dst = join(".",unpack( "CCCC", substr( $data, $pos+3, 4 ) ));

			if ( $host ne $new_dst ) {

				close($write_sock);

				$bak_destination = $new_dst;
				$host = $new_dst;

				$write_sock = IO::Socket::INET->new(
					Proto    => "udp",
					PeerPort => $server_port,
					PeerAddr => $host,
				  )
				  or my_exit("cannot open write socket: $@");

			}

			# TEID Control Plane ermitteln und als teid setzen
			$teid = substr( $data, 24, 4 );

		}

		if ($STEPS[$step] eq 'CPCR') {

			# prepare for DPCQ or DTX
			stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );

			if ($dl_str) {

				alarm $timeouts[$step];
				$SIG{ALRM} = \&my_alarm;
				prepareAndStartDownload($data);

			}

		}

		if ($STEPS[$step] eq 'DPCQ') {

			$write_sock = IO::Socket::INET->new(
				Proto    => "udp",
				PeerPort => $server_port,
				PeerAddr => $host,
			  )
			  or my_exit("cannot open write socket: $@");

			udp_send( "delete", $host, $server_port, $apn, $msisdn, $imsi,
				$hexcode, $sequence_number++ );

			stopwatch( \$sec, \$usec, $STEPS[ $step++ ] );

		}

	}

	if ( $#anotherpacket gt 0 )
	{
		my $crunchpkt = join("\t", @anotherpacket);
		dbg("PKT - got more than one packet per line from multiplexer: $#anotherpacket - " . 
			$anotherpacket[0] .", " . $anotherpacket[1] .", " . $anotherpacket[2] .", " . $anotherpacket[3] .
			",\n" . $anotherpacket[4], 1, 4);
		process_pkt( $crunchpkt );
	}
	
}




sub get_value {
	my ( $data, $id ) = @_;
	my $pos = 0;
	my $rw  = "";

	while ( length($data) ) {
		my $act_len = unpack( "n", substr( $data, 1, 2 ) );
		my $act_id = substr( $data, 0, 1 );
		if ( $act_id == $id ) {
			$rw = substr( $data, 3, $act_len );
			last;
		}
		$data = substr( $data, $act_len );
	}
	return $rw;
}




sub my_alarm {

	if ( $STEPS[$step] ne "CPCR" || @ggsnips == 0 ) {

		if ($STEPS[$step] ne 'DTX') {

			my_exit(
				"Plugin timed out during "
				  . $STEPS[$step]
				  . " after "
				  . $timeouts[$step]
				  . " seconds!",
				$CRITICAL
			);

		} else {

			#$dl_state = 0;
			$dl_running = 0;
			$dl_timeout_flag = 1;
	
			#process_pkt("$bak_source\t$bak_src_port\t$bak_destination\t$bak_dst_port");
			process_pkt("$bak_destination\t$bak_dst_port\t$bak_source\t$bak_src_port");

		}

	} else {

		# reset alarmhandler
		$SIG{'ALRM'} = \&my_alarm;
		alarm( $timeouts[$step] );

		# send first paket out to next IP
		$host = shift @ggsnips;

		udp_send(
			"create",     $host,    $server_port,
			$apn,         $msisdn,  $imsi,
			$gsn_address, $hexcode, $sequence_number++
		);

	}
}




sub my_exit {

	my ( $msg, $exitcode ) = @_;

	# No Exitcode? => UNKNOWN
	$exitcode = $UNKNOWN if ( !defined($exitcode) );

	# re-assign exit code if downloaded data was not valid
	if (
		(
			$dl_warning ||
			(defined($dl_timeout_warning) && $dl_timeout_flag) ||
			(defined($dl_not_found_warning) && $dl_not_found)
		) && ($exitcode == $OK || $exitcode == $UNKNOWN)
	) {
		$exitcode = $WARNING;
	}

	dbg(\%dl_data, 2, 5);

	# display stream and/or dump to file if enabled
	print $dl_stream if ($dl_dump);
	storeDataInFile() if ($dl_write_file);

	# Print errormsg
	print $EXITCODES{"$exitcode"} . ": " . $msg if ( defined($msg) );
	print ' | ' . $perfdata if ( $perfdata ne "" );
	print "\n";

	#gegebnenfalls sniffer beenden
	close($sniffer) if ( defined $sniffer );

	exit($exitcode);

}




sub stopwatch {

	my ( $sec, $usec, $step ) = @_;
	my ( $lsec, $lusec ) = gettimeofday;

	# Beim Initalisieren wird keine Zeit gestoppt
	if ( defined($step) ) {

		if ( $step !~ m/Q/i ) {

			my $diff = ($lsec + (0.000001 * $lusec) - $$sec - (0.000001 * $$usec));
			dbg("stopwatch:\t$step\t$lsec\t$lusec\t$$sec\t$$usec\t$diff\n", 1, 5);

			if ($step ne 'DTX') {

				$perfdata .= sprintf( "%s_ms=%.4f ", $step, ( 1000 * $diff ) );

			} else {

				if ($dl_not_found) {
					$perfdata .= sprintf("%s=not_found ", $step);
				} elsif ($dl_timeout_flag) {
					$perfdata .= sprintf("%s=timeout(%ss) ", $step, $dl_timeout);
				} else {
					$perfdata .= sprintf( "%s_ms=%.4f ", $step, ( 1000 * $diff ) );
				}

			}

		}

	} else {

		$perfdata = '';

	}

	$$sec  = $lsec;
	$$usec = $lusec;

	return;

}




sub print_version {
	print <<EOV;
$progname Version: 0.0.2 
EOV

	my_exit();
}




sub print_help {

	print <<EOU;

$progname -H 
Options are:

    -H <string>               Hostname (optional / default: via apn)
    -I <string>               Interfacename 
    -p <integer>              UDP Port (optional / default: 2123)
    -P <integer>              TCP Port of the multiplex process (optional /default: 2123)
    
    -a <string>               APN
    -m <string>               MISDN
    -i <string>               IMSI
    -g <string>               GSN-Addresses comma seperated 
                              (optional / default InterfaceIpAddress)
                         
    -U <string>               Peer-ID (default: "")
    -S <string>		      Password (default: "")

    -x <string>               additional hexcode to transmit (optional)
    -t <integer>,...          comma seperated list of seconds for each step before plugin will stop

    -s <integer>              seconds to sleep between CPCR and DPCQ (default: 1)
    
    -n <string>               comma seperated list of nameservers to query (optional) 

    -d <string>               download source 'hostname|ip|port|path'
    --dl-timeout <integer>    sets the download timeout in seconds (default: 10)
    --dl-not-found-warning    enable check result 'WARNING' if download results in '404 Not Found' and plugin result is not worse
    --dump-to-file <path>     write dump of downloaded data to file in <path> (string)
    --dump-to-screen          display dump of downloaded data on screen
    --dump-check              enable checking of content length
    --dump-warning            enable check result 'WARNING' if check of content length fails and plugin result is not worse
    --dump-length             enable display of content length in plugin output
    --dump-rate               enable display of download rate on plugin output
    --dump-rate-real          enable display of real download rate on plugin output

    -h, --help                display this help and exit
    -V, --version             output version information and exit
    
an example: $progname -I eth0 -a "blackberry.net" -m "+123456" -i "234103160051026"

EOU
	print "     The plugin's steps are: " . join( ", ", @STEPS ) . "\n";
	print '     By using parameter \'-d\', step \'DTX\' inserted right after \'CPCR\'' . "\n\n";

	my_exit();
}


