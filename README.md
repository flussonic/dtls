

Compilation
-----------


  ./rebar compile

Now launch:


  ./check.erl

DTLS server is listening on port 58036

Now try to connect from openssl:


  openssl s_client -dtls1 -connect 127.0.0.1:58036 -debug

