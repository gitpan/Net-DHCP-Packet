# Net::DHCP::Packet.pm
# Version 0.0
# Author: F. van Dun
#
# Some information about a DHCP packet from RFC 1497:
#	FIELD      OCTETS       DESCRIPTION
#   -----      ------       -----------
#
#   op            1  Message op code / message type.
#                    1 = BOOTREQUEST, 2 = BOOTREPLY
#   htype         1  Hardware address type, see ARP section in "Assigned
#                    Numbers" RFC; e.g., '1' = 10mb ethernet.
#   hlen          1  Hardware address length (e.g.  '6' for 10mb
#                    ethernet).
#   hops          1  Client sets to zero, optionally used by relay agents
#                    when booting via a relay agent.
#   xid           4  Transaction ID, a random number chosen by the
#                    client, used by the client and server to associate
#                    messages and responses between a client and a
#                    server.
#   secs          2  Filled in by client, seconds elapsed since client
#                    began address acquisition or renewal process.
#   flags         2  Flags (see figure 2).
#   ciaddr        4  Client IP address; only filled in if client is in
#                    BOUND, RENEW or REBINDING state and can respond
#                    to ARP requests.
#   yiaddr        4  'your' (client) IP address.
#   siaddr        4  IP address of next server to use in bootstrap;
#                    returned in DHCPOFFER, DHCPACK by server.
#   giaddr        4  Relay agent IP address, used in booting via a
#                    relay agent.
#   chaddr       16  Client hardware address.
#   sname        64  Optional server host name, null terminated string.
#   file        128  Boot file name, null terminated string; "generic"
#                    name or null in DHCPDISCOVER, fully qualified
#                    directory-path name in DHCPOFFER.
#   options     var  Optional parameters field.  See the options
#                    documents for a list of defined options.
#
#           Table 1:  Description of fields in a DHCP message
#
# Difference between bootp and DHCP:
#   The first four octets of the 'options' field of the DHCP message
#   contain the (decimal) values 99, 130, 83 and 99, respectively (this
#
#   is the same magic cookie as is defined in RFC 1497).  The remainder
#   of the 'options' field consists a list of tagged parameters that are
#   called "options".  All of the "vendor extensions" listed in RFC 1497
#   are also DHCP options.  A separate document gives the complete set of
#   options defined for use with DHCP [2].

package Net::DHCP::Packet;
use Socket;
use strict;
use Carp;
use Net::DHCP::Options;
use vars qw($VERSION);
$VERSION=0.0;

=pod

=head1 NAME

Net::DHCP::Packet - Object methods to create a DHCP packet.

=head1 SYNOPSIS

    use Net::DHCP::Packet;
	use strict;

	my $p = new Net::DHCP::Packet('Chaddr' => '0??BCDEF', 
				'Xid' => hex(0x9F0FD),
				'Ciaddr' => '0.0.0.0',
				'Siaddr' => '0.0.0.0', 'Hops' => 0);

=head1 DESCRIPTION

Represents a DHCP packet as specified in RFC 1533, RFC 2132.

=head2 CONSTRUCTORS

=item new

=item discover

=item request

=item decline

=item release


=head2 METHODS

=cut

# Opcode
sub BOOTREQUEST() 	{ 0x1 }
sub BOOTREPLY() 	{ 0x2 }

sub randomstring($) {
	my $len = shift;
	my $c;
	while ($len--) {
		$c .= chr(int (rand(255)));
	}
	return $c;
}

sub mac2str($$) {
	my $nibbles = shift(@_) * 2;
	my $str = unpack("H$nibbles", shift);
	return $str;
}

sub str2mac($) {
	pack('H*', shift);
}

=pod

=item op(BYTE opcode)

	Sets the opcode in the BOOTP type.
	Without argument, returns the BOOTP type.
	Argument is either:
	Net::DHCP::Packet::BOOTREQUEST() 	{ pack('C',0x1) }
	Net::DHCP::Packet::BOOTREPLY() 	{ pack('C',0x2) }

=cut
sub op {
	my ($self, $arg) = @_;
	$self->{op} = $arg unless (!defined ($arg));
	return $self->{op};
}
=pod

=item htype(BYTE hardware address type)

	Ex. '1' = 10mb ethernet

=cut
sub htype {
	my ($self, $arg) = @_;
	$self->{htype} = $arg unless (!defined ($arg));
	return $self->{htype};
}
=pod

=item hlen(BYTE hardware address length)

	For most NIC's, the MAC address has 6 bytes.

=cut
sub hlen {
	my ($self, $arg) = @_;
	$self->{hlen} = $arg unless (!defined ($arg));
	return $self->{hlen};
}
=pod

=item hops(BYTE number of hops)

	This field is incremented by each encountered DHCP relay agent.	
	
=cut
sub hops {
	my ($self, $arg) = @_;
	$self->{hops} = $arg unless (!defined ($arg));
	return $self->{hops};
}
=pod

=item xid(C4 transaction id)

	4 byte transaction id.

=cut
sub xid {
	my ($self, $arg) = @_;
	$self->{xid} = $arg unless (!defined ($arg));
	return $self->{xid};
}
=pod

=item secs(SHORT elapsed boot time)

	2 bytes for elapsed boot time.

=cut
sub secs {
	my ($self, $arg) = @_;
	$self->{secs} = $arg unless (!defined ($arg));	# unsigned Short. Exactly 16 bits.
	return $self->{secs};
}
=pod

=item flags(SHORT)

	2 bytes. 
	0x0000 = No broadcasts.
	0x1000 = Broadcasts.

=cut
sub flags {
	my ($self, $arg) = @_;
	$self->{flags} = $arg unless (!defined ($arg));
	return $self->{flags};
}
=pod

=item ciaddr(IP address)

	IP address is an ascci string like '10.24.50.3'.
	
=cut
sub ciaddr {
	my ($self, $arg) = @_;
	$self->{ciaddr} = $arg unless (!defined($arg));
	return $self->{ciaddr};
}
=pod

=item yiaddr(IP address)

=cut
sub yiaddr {
	my ($self, $arg) = @_;
	$self->{yiaddr} = $arg unless (!defined($arg));
	return $self->{yiaddr};
}
=pod

=item siaddr(IP address)

=cut
sub siaddr {
	my ($self, $arg) = @_;
	$self->{siaddr} = $arg unless(!defined($arg));
	return $self->{siaddr};
}
=pod

=item giaddr(IP address)

=cut
sub giaddr {
	my ($self, $arg) = @_;
	$self->{giaddr} = $arg unless (!defined($arg));
	return $self->{giaddr};
}
=pod

=item chaddr(MAC address)
	Hexadecimal string represenatation.
	Example: "0010A706DFFF" for 6 bytes mac address.
	
=cut
sub chaddr {
	my ($self, $arg) = @_;
	$self->{chaddr} = $arg unless (!defined ($arg));
	return $self->{chaddr};
}

=pod

=item sname(C64 servername)

	Optional 64 bytes null terminated string with server host name.

=cut
sub sname {
	my ($self, $arg) = @_;
	$self->{sname} = $arg unless (!defined ($arg));
	return $self->{sname};
}
=pod

=item file(C128 bootfilename)
	
	Optional

=cut
sub file {
	my ($self, $arg) = @_;
	$self->{file} = $arg unless (!defined ($arg));
	return $self->{file};
}

=pod

=item options(REF Net::DHCP::Options)

		Argument is reference to a Net::DHCP::Options object.
		Without argument, returns the Options object.

=cut
sub options {
	my ($self, $arg) = @_;
	$self->{options} = $arg unless (!defined ($arg));
	return $self->{options};
}
=pod

=item addOption($type, $value)

=cut
sub addOption {
	my ($self, $type, $value) = @_;
	$self->{options}->setOption($type,$value);
}

=item getOption($type)

=cut
sub getOption {
	my ($self, $type) = @_;
	$self->{options}->getOption(chr($type));
}
=pod

=item new(%ARGS)

	The hash %ARGS  can contain any of these keys:
	Op, Htype, Hlen, Hops, Xid, Secs, Flags, Ciaddr, Yiaddr, Siaddr, 
	Giaddr, Chaddr, Sname, File
	
=cut

sub new {
	my ($class, %args)	= @_;
	
	my $self = {};
	bless $self, $class;
	$self->op($args{Op} || BOOTREQUEST());
	$self->htype($args{Htype} || 1);	# 10mb ethernet
	$self->hlen($args{Hlen} || 6);		# Use 6 bytes MAC by default
	$self->hops($args{Hops} || 0);
	$self->xid($args{Xid} || randomstring(4));
	$self->secs($args{Secs} || 0);
	$self->flags($args{Flags} || 0);
	$self->ciaddr($args{Ciaddr} || 0);
	$self->yiaddr($args{Yiaddr} || 0);
	$self->siaddr($args{Siaddr} || 0);
	$self->giaddr($args{Giaddr} || 0);
	$self->chaddr($args{Chaddr} || randomstring(ord($self->hlen()) ) );
	$self->sname($args{Sname} || chr(0));
	$self->file($args{File} || chr(0));
	$self->{options} = new Net::DHCP::Options();
	return $self;
}
=pod

=item discover

	DHCP discover packet

=cut
sub discover {
	my ($class, %args)	= @_;
	
	my $self =$class->new(%args);
	$self->addOption(Net::DHCP::Options::MESSAGE_TYPE(),Net::DHCP::Options::DISCOVER());	
	$self->addOption(Net::DHCP::Options::CLASS_ID(),'MSFT 5.0');
	return $self;
}
=pod

=item request

	DHCP request packet
	
=cut
sub request {
	my ($class, %args)	= @_;
	
	my $self =$class->new(%args);
	$self->addOption(Net::DHCP::Options::MESSAGE_TYPE(),Net::DHCP::Options::REQUEST());	
	$self->addOption(Net::DHCP::Options::CLASS_ID(),'MSFT 5.0');
	return $self;
}
=pod

=item decline

	DHCP decline packet

=cut
sub decline {
	my ($class, %args)	= @_;
	
	my $self =$class->new(%args);
	$self->addOption(Net::DHCP::Options::MESSAGE_TYPE(),Net::DHCP::Options::DECLINE());	
	$self->addOption(Net::DHCP::Options::CLASS_ID(),'MSFT 5.0');
	return $self;
}
=pod

=item release

	DHCP release packet

=cut

sub release {
	my ($class, %args)	= @_;
	
	my $self =$class->new(%args);
	$self->addOption(Net::DHCP::Options::MESSAGE_TYPE(),Net::DHCP::Options::RELEASE());	
	$self->addOption(Net::DHCP::Options::CLASS_ID(),'MSFT 5.0');
	return $self;
}
=pod

=item serialize

	Converts a Net::DHCP::Packet to a string, ready to put on the network.

=cut
sub serialize {
	my ($self) = @_;
	my $bytes = undef;
	$bytes .= pack('C',$self->op());
	$bytes .= pack('C',$self->htype());
	$bytes .= pack('C',$self->hlen());
	$bytes .= pack('C',$self->hops());
	$bytes .= $self->xid();
	$bytes .= pack('S',$self->secs());
	$bytes .= pack('S',$self->flags());
	$bytes .= inet_aton($self->ciaddr());
	$bytes .= inet_aton($self->yiaddr());
	$bytes .= inet_aton($self->siaddr());
	$bytes .= inet_aton($self->giaddr());
	$bytes .= pack('C16', unpack('C16',$self->chaddr()));
	$bytes .= pack('C64', unpack('C64',$self->sname()));
	$bytes .= pack('C128', unpack('C128',$self->file()));
	$bytes .= $self->{options}->serialize();
	return $bytes;
}
=pod

=item marshall(string)

	The inverse of serialize. Converts a string, presumably a 
	received UDP packet, into a Net::DHCP::Packet.

=cut
sub marshall {
	use bytes;
	my ($self,$bytes) = @_;
	my $pos = 0;
	$self->{op} = unpack('C',substr($bytes,$pos++,1));
	$self->{htype} = unpack('C',substr($bytes,$pos++,1));
	$self->{hlen} = unpack('C',substr($bytes,$pos++,1));
	$self->{hops} = unpack('C',substr($bytes,$pos++,1));
	$self->{xid} = substr($bytes,$pos,4); $pos+=4;
	$self->{secs} = substr($bytes,$pos,2); $pos+=2;
	$self->{flags} = substr($bytes,$pos,2); $pos+=2;
	$self->{ciaddr} = inet_ntoa(substr($bytes,$pos,4)); $pos+=4;
	$self->{yiaddr} = inet_ntoa(substr($bytes,$pos,4)); $pos+=4;
	$self->{siaddr} = inet_ntoa(substr($bytes,$pos,4)); $pos+=4;
	$self->{giaddr} = inet_ntoa(substr($bytes,$pos,4)); $pos+=4;
	$self->{chaddr} = mac2str($self->{hlen},substr($bytes,$pos,16)); $pos+=16;	
	$self->{sname} = substr($bytes,$pos,64); $pos+=64;	
	$self->{sname} = substr($bytes,$pos,128); $pos+=128;	
	$self->{options} = new Net::DHCP::Options()->marshall(substr($bytes,$pos));
	return $self;
}
=pod

=item toString()

	Returns a textual representation of the packet, for debugging.

=cut
sub toString {
	my ($self) = @_;
	my $s = "";
	while ( my ($key, $value) = each (%$self) ) {
		next if ($key eq 'options');
		$s .= sprintf("%s = %s\n",$key,$value);
	}
	$s .= sprintf("options =\n %s\n", $self->{options}->toString());
	return $s;
}

=pod

=head1 AUTHOR

F. van Dun

=head1 BUGS

I only ran some simple tests on Windows 2000 with a W2K DHCP server and 
a USR DHCP server.
Not yet tested on Unix platform.

=head1 COPYRIGHT

This is free software. It can be distributed and/or modified under the same terms as
Perl itself.

=head1 SEE ALSO

perl(1), Net::DHCP::Options.

=cut

1;