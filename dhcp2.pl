use IO::Socket::INET;
use Net::DHCP::Packet;
use strict;
use bytes;

my $mac = 'E81BFDE12F00';
my $pdiscover = Net::DHCP::Packet->discover(Chaddr => $mac);

# Suppose 192.168.123.254 is a DHCP server.
my $sock = IO::Socket::INET->new(PeerAddr => '192.168.123.254',
								PeerPort => '67',
								LocalPort => '68',
								LocalAddr => '192.168.123.102',
								Proto    => 'udp') || die "Socketsend error: $!\n";

$sock->send($pdiscover->serialize()) || die "Error sending discovery:$!\n";
print "sent dhcp discover...\n";

#
# Receive DHCP OFFER
#
my $preply; 
do {
	my $buf;
	$sock->recv($buf,3000) || die "recv offer:$!\n";

	$preply = new Net::DHCP::Packet()->marshall($buf);	
 	#print $preply->toString();	
} until ( $preply->xid() eq $pdiscover->xid());
exit(1) unless ($preply->getOption(Net::DHCP::Options::MESSAGE_TYPE()) eq Net::DHCP::Options::OFFER());
  		
#
# Send DHCP Request
#
my $prequest = Net::DHCP::Packet->request(Siaddr => $preply->siaddr(), 
								Chaddr => $mac, 
								Ciaddr => $preply->yiaddr()
								);

$sock->send($prequest->serialize()) || die "Error sending request:$!\n";

#
# Receive DHCP ACK
#
my $ACK=0;
my $preply2;
do {
	my $buf;
	$sock->recv($buf,3000) || die "recv ack:$!\n";
	$preply2 = new Net::DHCP::Packet()->marshall($buf);
} until ($preply2->xid() eq $prequest->xid());

for ( $preply2->getOption(Net::DHCP::Options::MESSAGE_TYPE()) ) {
	($_ eq Net::DHCP::Options::NAK) && do {
		print "DHCP request refused by ".$preply2->siaddr().".\n";	
		last;
	};
	($_ eq Net::DHCP::Options::ACK) &&  do {
		print "Got IP address " . $preply2->yiaddr()." for $mac.\n";	
		$ACK=1;
		last;
	};
}
exit(1) unless ($ACK);
print "Sleeping 10 seconds...\n";
sleep(10);

#
# Release IP address
#
my $prelease = Net::DHCP::Packet->release(Siaddr => $preply2->siaddr(), 
								Chaddr => $mac, 
								Ciaddr => $preply2->yiaddr()
								);

$sock->send($prelease->serialize()) || die "Error sending release:$!\n";
print "Released address.\n";