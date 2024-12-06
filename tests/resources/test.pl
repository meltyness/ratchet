use Authen::TacacsPlus;

my $username_to_use = "username";
my $password_to_use = "123456";
my $auth_mode_to_use = 2;

if($ARGV[0] eq "negative") {
	$password_to_use = "1234567";
} elsif ($ARGV[0] eq "wat") {
	$username_to_use = "ｕｓｅｒｎａｍｅ";
} elsif ($ARGV[0] eq "db") {
	$username_to_use = "user2";
	$password_to_use = "unbelievable_password";
} elsif ($ARGV[0] eq "dbreject") {
	$username_to_use = "user1";
	$password_to_use = "extremely_secure_pass"; # we can only hope to learn from all of our mistakes
}  
elsif ($ARGV[0] eq "ascii") {
	$auth_mode_to_use = undef;
}

$tac = new Authen::TacacsPlus(Host=>"127.0.0.1",
			      Key=>"testing123",
			      Port=>'44449',
			      Timeout=>3);


if ($tac->authen($username_to_use, $password_to_use, $auth_mode_to_use)) {
	print "Success!\n";
	$tac->close();
	exit;
} else {
	print "test.pl trace: " . Authen::TacacsPlus::errmsg() . "\n";
	die "Authentication failed for test account.";
}

1
