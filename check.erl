#!/usr/bin/env escript
%%
%%! -pa ebin

-mode(compile).


main([]) ->
  {ok, _} = application:ensure_all_started(ssl),

  {ok, Sock} = gen_udp:open(0, [binary,{active,once}]),

  {ok, {_, LocalPort}} = inet:sockname(Sock),
  io:format("DTLS server is listening on port ~p\n", [LocalPort]),

  
  % % This is an example of peer fingerprint from Mozilla WebRTC SDP
  % PeerFingerprint = <<"FA:2E:0E:17:A9:41:62:02:5B:17:B4:65:BC:00:BA:BD:99:8E:7E:D0:ED:A8:2B:71:E6:B1:F9:6B:1D:9E:FE:83">>,
  % PeerIdentity = {sha256, PeerFingerprint},
  PeerIdentity = undefined,

  CertFile = generate,
  KeyFile = generate,

  % Role = client,
  Role = server,

  Dtls = dtls4srtp:new(Role, self(), PeerIdentity, CertFile, KeyFile),
  {sha256, _Fingerprint} = dtls4srtp:get_self_cert_fingerprint(Dtls),

  Role == client andalso dtls4srtp:start(Dtls),

  loop(Sock, Dtls).


loop(Sock, Dtls) ->
  Msg = receive M -> M end,

  case Msg of
    {udp, Sock, SrcHost, SrcPort, <<T, 16#FE, _/binary>> = Bin} when T == 255; T < 25 ->
      inet:setopts(Sock, [{active,once}]),
      put(peer, {SrcHost, SrcPort}),
      dtls4srtp:on_received(Dtls, Bin);

    {dtls, flight, Data} ->
      {SrcHost, SrcPort} = get(peer),
      ok = gen_udp:send(Sock, SrcHost, SrcPort, Data);

    {dtls, key_material, SrtpParams} ->
      io:format("Got key material, that's all: ~p\n", [SrtpParams])
  end,
  loop(Sock, Dtls).

