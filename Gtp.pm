#!/usr/bin/perl -w

# COPYRIGHT:
#  
# This software is Copyright (c) 2008 NETWAYS GmbH, Christian Doebler 
#                                <support@netways.de>
# 
# (Except where explicitly superseded by other copyright notices)
# 
# 
# LICENSE:
# 
# This work is made available to you under the terms of Version 2 of
# the GNU General Public License. A copy of that license should have
# been provided with this software, but in any event can be snarfed
# from http://www.fsf.org.
# 
# This work is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 or visit their web page on the internet at
# http://www.fsf.org.
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
# this Software, to NETWAYS GmbH, you confirm that
# you are the copyright holder for those contributions and you grant
# NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.
#
# Nagios and the Nagios logo are registered trademarks of Ethan Galstad.


package Gtp;

use strict;
use warnings;

use Data::Dumper;

use vars qw($VERSION @ISA @EXPORT);

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw($VERSION);




################################################
# GLOBAL VARIABLES
################################################

sub new {
	my ($package) = @_;

	my $self = bless {

		debug => 0,

		ip => undef,
		gw => undef,
		dev => undef,

		header => {},
		header_stream => undef,
		header_length => undef,

		data => undef,

		packet => undef,

	}, $package;

	return $self;
}




################################################
# DATA CONVERSION
################################################

sub bin2dec {
    return unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
}



sub dec2hex {
	my ($dec, $bytes) = @_;
	my $hex = sprintf("%02x", $dec);
	my $length = ($bytes * 2) - length($hex);
	return "0" x $length . $hex;
} 



sub hex2dec {
	return hex(shift);
}



sub sumArr {
	my (@arr) = @_;
	my $factor = 1;
	my $sum = 0;
	for (my $x = $#arr; $x >= 0; $x--) {
		$sum += ($arr[$x] * $factor);
		$factor *= 256;
	}
	return $sum;
}




################################################
# GTP-DATA READ / WRITE
################################################

sub packet {
	my $self = shift;
	$self->buildheader();
	$self->{header}->{length} = length($self->{header_stream}) - 8 + length($self->{data});
	$self->buildheader();
	$self->{packet} = $self->{header_stream} . $self->{data};
	return $self->{packet};
}



sub set {
	my ($self, $args) = @_;
	while (my ($key, $value) = each(%{$args})) {
		if (ref($value) eq "HASH") {
			while (my ($ikey, $ivalue) = each(%{$value})) {
				$self->{$key}->{$ikey} = $ivalue;
			}
		} else {
			$self->{$key} = $value;
		}
	}
}




################################################
# GTP-PAYLOAD HANDLING
################################################

sub getdata {
	my $self = shift;
	$self->getheader();
	return unless (defined($self->{header_length}));
	$self->{data} = substr($self->{packet}, $self->{header_length}, length($self->{packet}) - $self->{header_length});
}




################################################
# GTP-HEADER HANDLING
################################################

sub showheader {
	my $self = shift;
	if (defined($self->{header})) {
		my %header = %{$self->{header}};
		while (my ($key, $value) = each(%header)) {
			print "$key => $value\n";
		}
	} else {
		print "no header data found!\n"
	}
}



sub getheader {

	my $self = shift;

	return unless (defined($self->{packet}));

	my $data = $self->{packet};
	my $pos = 1;

	my ($version, $pt, $spare, $ext, $snf, $pn) = unpack("A3AAAAA", unpack("B8", $data));
	my $msg_type = ord(substr($data, $pos++, 1));
	my @length = (ord(substr($data, $pos++, 1)), ord(substr($data, $pos++, 1)));
	my @teid = (ord(substr($data, $pos++, 1)), ord(substr($data, $pos++, 1)), ord(substr($data, $pos++, 1)), ord(substr($data, $pos++, 1)));

	my %header = (
		'version'			=> bin2dec($version),
		'protocol_type'			=> bin2dec($pt),
		'spare_bit'			=> bin2dec($spare),
		'extension_header_flag'		=> bin2dec($ext),
		'sequence_number_flag'		=> bin2dec($snf),
		'n_pdu_number_flag'		=> bin2dec($pn),
		'message_type'			=> $msg_type,
		'length'			=> sumArr(@length),
		'teid'				=> sumArr(@teid)
	);

	if ($header{'sequence_number_flag'} == 1 || $header{'n_pdu_number_flag'} == 1 || $header{'extension_header_flag'} == 1) {
		my @seq_num = (ord(substr($data, $pos++, 1)), ord(substr($data, $pos++, 1)));
		$header{'sequence_number'} = sumArr(@seq_num);
		my $npdu_num = ord(substr($data, $pos++, 1));
		$header{'n_pdu_number'} = $npdu_num;
		my $ext_type = ord(substr($data, $pos++, 1));
		$header{'next_extension_header_type'} = $ext_type;
	}

	if ($self->{debug} == 1) {
		while (my ($key, $value) = each(%header)) {
			print "$key => $value\n";
		}
	}

	$self->{header_length} = $pos;
	$self->{header} = \%header;

}



sub buildheader {

	my $self = shift;
	my %header = %{$self->{header}};

	my $length = dec2hex($header{'length'}, 2);
	my $teid = dec2hex($header{'teid'}, 4);

	my @built_header = (
		(($header{'version'}<<5) + ($header{'protocol_type'}<<4) + ($header{'spare_bit'}<<3) + ($header{'extension_header_flag'}<<2) + ($header{'sequence_number_flag'}<<1) + ($header{'n_pdu_number_flag'})),
		$header{'message_type'},
		hex2dec(substr($length, 0, 2)),
		hex2dec(substr($length, 2, 2)),
		hex2dec(substr($teid, 0, 2)),
		hex2dec(substr($teid, 2, 2)),
		hex2dec(substr($teid, 4, 2)),
		hex2dec(substr($teid, 6, 2)),
	);

	if ($header{'sequence_number_flag'} == 1 || $header{'n_pdu_number_flag'} == 1 || $header{'extension_header_flag'} == 1) {
		my $seq_num = dec2hex($header{'sequence_number'}, 2);
		push(@built_header, hex2dec(substr($seq_num, 0, 2)));
		push(@built_header, hex2dec(substr($seq_num, 2, 2)));
		push(@built_header, $header{'n_pdu_number'});
		push(@built_header, $header{'next_extension_header_type'});	
	}

	my $new_header = '';
	for my $element (@built_header) {
		$new_header .= chr($element);
	}

	$self->{header_stream} = $new_header;

}




################################################
# MISC FUNCTIONS
################################################

sub hexdump {
	my $dump_data = shift;
	for (my $x = 0; $x < length($dump_data); $x++) {
		my $next = $x + 1;
		printf("%02x ", ord(substr($dump_data, $x, 1)));
		print "  " if (!($next % 8));
		print "\n" if (!($next % 16));
	}
	print "\n";
}



1;
