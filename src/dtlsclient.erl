-module(dtlsclient).

-export([start/4, start/5]).
-export([run_proxy/6]).


start(Host, Port, CertFile, KeyFile) ->
  start(client, Host, Port, CertFile, KeyFile).

start(Role, Host, Port, CertFile, KeyFile) ->
  Proxy = spawn_link(?MODULE, run_proxy, [self(), Role, Host, Port, CertFile, KeyFile]),
  receive
    {Proxy, port, LocalPort} -> {ok, Proxy, LocalPort}
  after
    1000 ->
      exit(Proxy, kill),
      error({local_port_timeout})
  end.


run_proxy(Owner, Role, Host, Port, CertFile, KeyFile) ->
  {ok, Sock} = gen_udp:open(0, [binary,{active,once}]),

  {ok, {_, LocalPort}} = inet:sockname(Sock),
  Owner ! {self(), port, LocalPort},

  Dtls = dtls4srtp:new(Role, self(), undefined, CertFile, KeyFile),
  Role == client andalso dtls4srtp:start(Dtls),
  proxy_loop(Host, Port, Sock, Dtls).

proxy_loop(Host, Port, Sock, Dtls) ->
  {NewHost, NewPort} = receive
    {udp, Sock, SrcHost, SrcPort, Bin} when Host == undefined ->
      inet:setopts(Sock, [{active,once}]),
      dtls4srtp:on_received(Dtls, Bin),
      {SrcHost, SrcPort};
    {udp, Sock, Host, Port, Bin} ->
      inet:setopts(Sock, [{active,once}]),
      dtls4srtp:on_received(Dtls, Bin),
      {Host, Port};
    {dtls, flight, Data} ->
      ok = gen_udp:send(Sock, Host, Port, Data),
      {Host, Port};
    stop ->
      dtls4srtp:shutdown(Dtls),
      exit(normal);
    Other ->
      io:format("proxy_loop: unexpected ~120P~n", [Other, 40]),
      {Host, Port}
  end,
  proxy_loop(NewHost, NewPort, Sock, Dtls).


