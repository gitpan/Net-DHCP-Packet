# Net::DHCP::Packet.pm
# Version 0.0
# Author: F. van Dun

package Net::DHCP::Options;
use Carp;
use vars qw($VERSION);
$VERSION=0.0;

=pod

=head1 NAME

Net::DHCP::Options - Object methods to create and access DHCP options.

=head1 DESCRIPTION

Used by Net::DHCP::Packet.

=head2 CONSTRUCTORS

=item new


=head2 METHODS

=item getOption($key)

=item setOption($key, $value)

=item serialize

=item marshall($bytes)

=item toString

=head1 AUTHOR

F. van Dun

=head1 COPYRIGHT

This is free software. It can be distributed and/or modified under the same terms as
Perl itself.

=head1 SEE ALSO

perl(1), Net::DHCP::Packet.

=cut


# Message Types are 1 byte
sub DISCOVER() 	{ pack('C',0x1) }
sub OFFER() 	{ pack('C',0x2) }
sub REQUEST() 	{ pack('C',0x3) }
sub DECLINE()	{ pack('C',0x4) }
sub ACK()		{ pack('C',0x5) }
sub NAK()		{ pack('C',0x6) }
sub RELEASE()	{ pack('C',0x7) }
sub INFORM()	{ pack('C',0x8) }

# Option Fields
sub MESSAGE_TYPE() { 0x35 }
sub SERVER_IP() { 0x36}
sub PARAMETERS() { 0x37 }
sub CLIENT_ID() { 0x3d }
sub REQUEST_IP() { 0x32 }
sub RENEW() { 0x3a }
sub REBIND() { 0x3b }
sub SUBNET_MASK() { 0x01 }
sub GATEWAY_ADDRESS() { 0x03 }
sub DOMAIN() { 0x0f }
sub DNS_SERVER() { 0x06 }
sub HOSTNAME() { 0x0c }
sub RESERVED() { 0xfb }
sub CLASS_ID() { 0x3c }

# MAGIC_COOKIE for DHCP (oterhwise it is BOOTP)
sub MAGIC_COOKIE {pack('C4', 99,130,83,99)};

sub serialize {
	my ($self) = @_;
	my $bytes = MAGIC_COOKIE;
	while ( my ($key, $value) = each (%$self) ) {
		$bytes .= pack('C', $key);
		$bytes .= pack('C/A*', $value);
	}
	$bytes .= pack('C',255);
}

sub toString {
	my ($self) = @_;
	my $s = "";
	while ( my ($key, $value) = each (%$self) ) {
		$s .= sprintf("%d = %s\n",ord($key),$value);
	}
	return $s;
}


sub marshall {
	use bytes;
	my ($self, $bytes) = @_;
	my $pos = 4;	# Skip magic cookie
	my $total = length($bytes);
	
	while ($pos < $total) {
		my $type = substr($bytes,$pos++,1);
		last if ($type eq chr(255));	# Type 'FF' signals end of options.
		my $len = ord(substr($bytes,$pos++,1));
		my $option = substr($bytes,$pos,$len);
		$pos+=$len;
		$self->setOption($type,$option);
	}	
	return $self;
}

sub setOption {
	my ($self,$key,$value) = @_;
	$self->{$key} = $value;
}

sub getOption {
	my ($self,$key) = @_;
	return $self->{$key};
}


sub new {
	my ($class) = (@_);
	my $self = {};
	
	bless $self, $class;
	return $self;
}

1;