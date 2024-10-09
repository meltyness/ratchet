use Authen::TacacsPlus;

$tac = new Authen::TacacsPlus(Host=>"127.0.0.1",
			      Key=>"testing123",
			      Port=>'44449',
			      Timeout=>15);

$tac->authen("usn", "123456", 2);

Authen::TacacsPlus::errmsg();

$tac->close();
