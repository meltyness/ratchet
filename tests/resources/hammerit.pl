use Authen::TacacsPlus;

my $username_to_use = "username";
my $password_to_use = "123456";

if($ARGV[0] eq "negative") {
	$password_to_use = "1234567";
} elsif ($ARGV[0] eq "wat") {
	$username_to_use = "ｕｓｅｒｎａｍｅ";
} elsif ($ARGV[0] eq "db") {
	$username_to_use = "user2";
	$password_to_use = "unbelievable_password";
}
while(1) {
my $tac = new Authen::TacacsPlus(Host=>"127.0.0.1",
			      Key=>"testing123",
			      Port=>'44449',
			      Timeout=>0);


if ($tac->authen($username_to_use, $password_to_use, 2)) {
	print "Success!\n" if rand(1000) > 900;
	$tac->close();
	#exit;
} else {
	#print "test.pl trace: " . Authen::TacacsPlus::errmsg() . "\n";
	#die "Authentication failed for test account.";
}
}
1