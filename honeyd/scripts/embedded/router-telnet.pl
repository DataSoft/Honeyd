#!/usr/bin/perl
# Copyright 2002 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# For the license refer to the main source code of Honeyd.
#
# Don't echo Will Echo Will Surpress Go Ahead
$return = pack('ccccccccc', 255, 254, 1, 255, 251, 1, 255, 251, 3);
syswrite STDOUT, $return, 9;

$string =
"Users (authorized or unauthorized) have no explicit or\r
implicit expectation of privacy.  Any or all uses of this\r
system may be intercepted, monitored, recorded, copied,\r
audited, inspected, and disclosed to authorized site,\r
and law enforcement personnel, as well as to authorized\r
officials of other agencies, both domestic and foreign.\r
By using this system, the user consents to such\r
interception, monitoring, recording, copying, auditing,\r
inspection, and disclosure at the discretion of authorized\r
site.\r
\r
Unauthorized or improper use of this system may result in\r
administrative disciplinary action and civil and criminal\r
penalties.  By continuing to use this system you indicate\r
your awareness of and consent to these terms and conditions\r
 of use.  LOG OFF IMMEDIATELY if you do not agree to the\r
conditions stated in this warning.\r
\r
\r
\r
User Access Verification\r
";

syswrite STDOUT, $string;

$count = 0;
while ($count < 3) {
  do {
    $count++;
    syswrite STDOUT, "\r\n";
    $word = read_word("Username: ", 1);
  } while (!$word && $count < 3);
  if ($count >= 3 && !$word) {
    exit;
  }
  $password = read_word("Password: ", 0);
  if (!$password) {
    syswrite STDOUT, "% Login invalid\r\n";
  } else {
    syswrite STDERR, "Attempted login: $word/$password";
    syswrite STDOUT, "% Access denied\r\n";
  }
}

exit;

sub read_word {
  local $prompt = shift;
  local $echo = shift;
  local $word;

  syswrite STDOUT, "$prompt";

  $word = "";
  $alarmed = 0;
  eval {
    local $SIG{ALRM} = sub { $alarmed = 1; die; };
    alarm 30;
    $finished = 0;
    do {
      $nread = sysread STDIN, $buffer, 1;
      die unless $nread;
      if (ord($buffer) == 0) {
	; #ignore
      } elsif (ord($buffer) == 255) {
	sysread STDIN, $buffer, 2;
      } elsif (ord($buffer) == 13 || ord($buffer) == 10) {
	syswrite STDOUT, "\r\n" if $echo;
	$finished = 1;
      } else {
	syswrite STDOUT, $buffer, 1 if $echo;
	$word = $word.$buffer;
      }
    } while (!$finished);
    alarm 0;
  };
  syswrite STDOUT, "\r\n" if $alarmed || ! $echo;
  if ($alarmed) {
    syswrite STDOUT, "% $prompt timeout expired!\r\n";
    return (0);
  }

  return ($word);
}
