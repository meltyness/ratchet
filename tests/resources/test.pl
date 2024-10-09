use Authen::TacacsPlus;

$tac = new Authen::TacacsPlus(Host=>"127.0.0.1",
			      Key=>"testing123",
			      Port=>'44449',
			      Timeout=>15);

if ($tac->authen("usn", "123456", 2)) {
	print "Success!\n";
	$tac->close();
	exit;
} else {
	print "test.pl trace: " . Authen::TacacsPlus::errmsg() . "\n";
	die "Authentication failed for test account.";
}

1