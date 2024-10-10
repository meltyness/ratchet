use Authen::TacacsPlus;

my $password_to_use = "123456";

if($ARGV[0] eq "negative") {
	$password_to_use = "1234567"
}

$tac = new Authen::TacacsPlus(Host=>"127.0.0.1",
			      Key=>"testing123",
			      Port=>'44449',
			      Timeout=>15);


if ($tac->authen("username", $password_to_use, 2)) {
	print "Success!\n";
	$tac->close();
	exit;
} else {
	print "test.pl trace: " . Authen::TacacsPlus::errmsg() . "\n";
	die "Authentication failed for test account.";
}

1
