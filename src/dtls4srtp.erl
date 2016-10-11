% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil -*-
-module(dtls4srtp).

% -compile(export_all).

-behaviour(gen_fsm).


-include_lib("ssl/src/ssl_internal.hrl").
-include_lib("ssl/src/ssl_cipher.hrl").
-include_lib("public_key/include/public_key.hrl"). 
-include("dtls4srtp_handshake.hrl").
-include("dtls4srtp_record.hrl").
-include("dtls4srtp.hrl"). 

%external api.
-export([new/5, start/1, start/5, shutdown/1, on_received/2, set_peer_cert_fingerprint/2, get_self_cert_fingerprint/1]).
-export([gen_srtp_key_material/2]).

% gen_fsm callbacks.
-export([init/1, hello_clt/2, hello_srv/2, certify/2, certify_srv/2, cipher/2,  connection/2,
	handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).
% internal
-export([retrans_timer_expired/1]).

%% TODO: generate key pair and certificate
%% public_key:pem_entry_decode returns #'ECPrivateKey' which can be crafted with keys returned by crypto:generate_key(ecdh, secp256r1)


-record(state, {
        role,               % client | server
        owner,              % pid() or name of a registered process. 
        epoch = 0, 
        seq_no = 0,
        tmr,
        tmrV = 1,
        flight_begin_epoch,
        flight_begin_seq_no,
        flight_begin_cs,
        msg_seq_s = 0,
        msg_seq_r = 0,
        srtp_params,         % #srtp_params from dtls4srtp.hrl.
        peer_cert_fingerprint, % {Algorithm, binary()}.
        self_cert_fingerprint, % {Algorithm, binary()}.
        file_ref_db,         % ets()
        cert_db_ref,         % ref()
        cert_db,
        session_cache,
        connection_states,     % #connection_states{} from ssl_record.hrl
        flights_tosend = [],   % binary() buffer of incomplete records.
        retrans_timer,         % Ref() of timer.
        retrans_timerV = 1,    % time(unit:second) to retransmit the last flight.
        tls_handshake_history, % tls_handshake_history()
        session,             % #session{} from dtls4srtp_handshake.hrl
        client_certificate_requested = false,
        key_algorithm,       % atom as defined by cipher_suite
        hashsign_algorithm,  % atom as defined by cipher_suite
        signature_types,    % {rsa_digest_type(), rsa | dsa | ecdsa} as returned from public_key:pkix_sign_types/1
        public_key_info,     % PKIX: {Algorithm, PublicKey, PublicKeyParams}
        private_key,         % PKIX: #'RSAPrivateKey'{}
        diffie_hellman_params, % PKIX: #'DHParameter'{} relevant for server side
        diffie_hellman_keys, % {PublicKey, PrivateKey}
        psk_identity,        % binary() - server psk identity hint
        srp_params,          % #srp_user{}
        srp_keys,            % {PublicKey, PrivateKey}
        premaster_secret,    %
        client_ecc          % {Curves, PointFmt}
    }).


% -type state_name()           :: hello_clt | hello_srv | certify | certify_srv | cipher | connection.
% -type gen_fsm_state_return() :: {next_state, state_name(), #state{}} |
% 				{next_state, state_name(), #state{}, timeout()} |
% 				{stop, term(), #state{}}.

%% external Interfaces.
start(Role, Owner, PeerCertFingerP, CertFile, PKeyFile) ->
    {ok, Pid} = gen_fsm:start(?MODULE, {Role, Owner, PeerCertFingerP, CertFile, PKeyFile}, []),
    gen_fsm:send_event(Pid, start),
    Pid.

new(Role, Owner, PeerCertFingerP, CertFile, PKeyFile) ->
    {ok, Pid} = gen_fsm:start(?MODULE, {Role, Owner, PeerCertFingerP, CertFile, PKeyFile}, []),
    Pid.

% set_owner(PRef, OwnerPid) ->
%     gen_fsm:send_all_state_event(PRef, {set_owner, OwnerPid}).

start(PRef) ->
    gen_fsm:send_event(PRef, start).

shutdown(PRef) ->
    gen_fsm:send_all_state_event(PRef, shutdown).

on_received(PRef, Data) when is_binary(Data) ->
    ReceivedFlights = dtls4srtp_record:decode_flight(Data),
    lists:foreach(fun(R) -> gen_fsm:send_event(PRef, {received_peer_record, R}) end, ReceivedFlights).

set_peer_cert_fingerprint(PRef, FingerP) ->
    gen_fsm:send_all_state_event(PRef, {peer_cert_fingerprint, FingerP}).

-spec get_self_cert_fingerprint(pid()) -> {atom(), binary()}.
get_self_cert_fingerprint(PRef) ->
    gen_fsm:sync_send_all_state_event(PRef, self_cert_fingerprint).

retrans_timer_expired(PRef) ->
    gen_fsm:send_all_state_event(PRef, retrans_timer_expired).




%% callbacks for gen_fsm.
init({Role, Owner, PeerCertFingerPrint, CertFile, KeyFile}) ->
    State0 = initial_state(Role, Owner, PeerCertFingerPrint),
    Handshake = ssl_handshake:init_handshake_history(),
    TimeStamp = calendar:datetime_to_gregorian_seconds({date(), time()}),
    _ = erlang:monitor(process, Owner),
    Hello = case Role of
      client -> hello_clt;
      server -> hello_srv
    end,
    try make_secure_identities(Role, CertFile, KeyFile) of
    	{ok, Ref, CertDbHandle, FileRefHandle, CacheHandle, OwnCert, Key, DHParams} ->
	    Session = State0#state.session,
      SignatureTypes = signature_types(OwnCert),
	    State = State0#state{
				 tls_handshake_history = Handshake,
				 session = Session#session{own_certificate = OwnCert,
							   time_stamp = TimeStamp},
			         file_ref_db = FileRefHandle,
				 cert_db_ref = Ref,
				 cert_db = CertDbHandle,
				 session_cache = CacheHandle,
         signature_types = SignatureTypes,
         self_cert_fingerprint = make_fingerprint(SignatureTypes, OwnCert),
				 private_key = Key,
				 diffie_hellman_params = DHParams,
				 flights_tosend = []},
	    {ok, Hello, State}
    catch
	throw:Error ->
	    {stop,Error}
    end.

%% Client hello state
-spec hello_clt(start | {received_peer_record, #dtls_record{}},
	    #state{}) -> gen_fsm_state_return(). 
hello_clt(start, #state{role=client, owner=Owner, epoch=Epoch, seq_no=SeqNo, msg_seq_s=MsgSeqS, 
			connection_states=ConnectionStates0, tls_handshake_history=Handshake0} = State0) ->
    Pending = ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = Pending#connection_state.security_parameters,
    ClientHello = dtls4srtp_handshake:client_hello(MsgSeqS, SecParams#security_parameters.client_random),
    HS1 = ssl_handshake:update_handshake_history(Handshake0, ClientHello),
    {ClientHelloBin, CS1} = encode_client_hello(ClientHello, ConnectionStates0, Epoch, SeqNo),
    Owner ! {dtls, flight, ClientHelloBin},
    {ok, Tref} = timer:apply_after(1000, ?MODULE, retrans_timer_expired, [self()]),
    State1 = State0#state{seq_no = SeqNo+1,
                          tmr = Tref,
                          tmrV = 1,
                          msg_seq_s = MsgSeqS+1,
                          flights_tosend = [{?HANDSHAKE, ClientHello}],
                          flight_begin_epoch = Epoch,
                          flight_begin_seq_no = SeqNo+1,
                          flight_begin_cs = ConnectionStates0,
                          connection_states=CS1,
			  tls_handshake_history = HS1},
    {next_state, hello_clt, State1};

hello_clt({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?HELLO_VERIFY_REQUEST, fragment=HelloVerifyRequest}}, 
      #state{owner=Owner, role = client, tmr=Tmr, epoch=Epoch, seq_no=SeqNo, msg_seq_s=MsgSeqS, msg_seq_r=MsgSeqR, connection_states=CS0} = State0) ->
    #hello_verify_request{protocol_version = {16#fe, _}, cookie = Cookie} = dtls4srtp_handshake:dec_hs(?HELLO_VERIFY_REQUEST, HelloVerifyRequest),
    timer:cancel(Tmr),
    Handshake0 = ssl_handshake:init_handshake_history(),
    Pending = ssl_record:pending_connection_state(CS0, read),
    SecParams = Pending#connection_state.security_parameters,
    ClientHello = dtls4srtp_handshake:client_hello(MsgSeqS, SecParams#security_parameters.client_random, Cookie),
    HS1 = ssl_handshake:update_handshake_history(Handshake0, ClientHello),
    {ClientHelloBin, CS1} = encode_client_hello(ClientHello, CS0, Epoch, SeqNo),
    Owner ! {dtls, flight, ClientHelloBin},
    {ok, Tref} = timer:apply_after(1000, ?MODULE, retrans_timer_expired, [self()]),
    State1 = State0#state{seq_no = SeqNo+1,
                          tmr = Tref,
                          tmrV = 1,
                          msg_seq_s=MsgSeqS+1,
                          msg_seq_r=MsgSeqR+1,
                          flights_tosend = [{?HANDSHAKE, ClientHello}],
                          flight_begin_epoch = Epoch,
                          flight_begin_seq_no = SeqNo+1,
                          flight_begin_cs = CS0,
                          connection_states=CS1,
                          tls_handshake_history = HS1},
    {next_state, hello_clt, State1};

hello_clt({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?SERVER_HELLO, content_raw=Raw, message_seq=MsgSeqR, fragment=ServerHello}}, 
      #state{role = client, tmr=Tmr, msg_seq_r = MsgSeqR, connection_states=CS0, session=Session0, tls_handshake_history=HS0} = State0) ->
    #dtls_server_hello{server_version = {16#fe, _} = Version,
                random = Random,
                session_id = SessionID,
                cipher_suite = CipherSuite,
                compression_method = CompMethod,
                renegotiation_info = _RenegotiationInfo,
                hash_signs = _HashSigns,
                elliptic_curves = _EllipticCurves,
                use_srtp=UseSrtp} = dtls4srtp_handshake:dec_hs(?SERVER_HELLO, ServerHello),
    State00 = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    CS00=ssl_record:set_renegotiation_flag(true, CS0),
    CS1 = hello_pending_connection_states(client, {3, 3}, CipherSuite, Random, CompMethod, CS00),
    {KeyAlgorithm, _, _, _} = ssl_cipher:suite_definition(CipherSuite),
    % io:format("Server has selected cipher suite ~120p~n", [ssl_cipher:suite_definition(CipherSuite)]),
    PremasterSecret = make_premaster_secret(Version, KeyAlgorithm),
    HashsignAlgorithm = default_hashsign(Version, KeyAlgorithm),
    timer:cancel(Tmr),

    SrtpParams = case UseSrtp of
      #use_srtp{protection_profile = ProtectionProfile, mki = MKI} ->
        #srtp_params{
          protection_profile_name = proplists:get_value(ProtectionProfile, ?PROTECTION_PROFILE_NAMES),
          protection_profile_detail=proplists:get_value(ProtectionProfile, ?PROTECTION_PROFILE_DETAILS),
          mki=MKI };
      undefined ->
        undefined
    end,

    State1 = State00#state{session=Session0#session{session_id=SessionID},
                        connection_states=CS1,
                        key_algorithm=KeyAlgorithm,
                        hashsign_algorithm=HashsignAlgorithm,
                        premaster_secret=PremasterSecret,
                        flights_tosend = [],
                        srtp_params=SrtpParams},
    {next_state, certify, State1#state{msg_seq_r=MsgSeqR+1}};

hello_clt({received_peer_record, #dtls_record{} = R}, #state{msg_seq_r = MsgSeqR}=St) ->
    io:format("receieved unexpected record ~160P at state[~p:~w].~n", [R, 50, hello_clt, MsgSeqR]),
    {next_state, hello_clt, St}.




hello_srv({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?CLIENT_HELLO, content_raw=Raw, message_seq=MsgSeqR, fragment=ClientHello}}, 
          #state{msg_seq_r=MsgSeqR, connection_states=CS0, tls_handshake_history=HS0} = State0) ->
    #dtls_client_hello{client_version = {16#fe, _} = Version,
        random = Random,
        cipher_suites = CipherSuites,
        extensions = _Extensions} = dtls4srtp_handshake:dec_hs(?CLIENT_HELLO, ClientHello),
    % We put raw into list to avoid hitting ssl_handshake:update_handshake_history first clause
    HS1 = ssl_handshake:update_handshake_history(HS0, [Raw]),
    % io:format("Client hello: ~160P~n   -> ~160P~n", [Raw, 50, HS1, 50]),

    CipherSuite = dtls4srtp_handshake:choose_cipher_suite(CipherSuites),
    {KeyAlgorithm, _, _, _} = ssl_cipher:suite_definition(CipherSuite),
    % io:format("Server has selected cipher suite ~120p~n", [ssl_cipher:suite_definition(CipherSuite)]),
    PremasterSecret = make_premaster_secret(Version, KeyAlgorithm),
    HashsignAlgorithm = default_hashsign(Version, KeyAlgorithm),


    CS00=ssl_record:set_renegotiation_flag(true, CS0),
    CS1 = hello_pending_connection_states(server, {3, 3}, CipherSuite, Random, 0, CS00),

    ProtectionProfile = ?SRTP_AES128_CM_HMAC_SHA1_80,
    SrtpParams = #srtp_params{
        protection_profile_name = proplists:get_value(ProtectionProfile, ?PROTECTION_PROFILE_NAMES),
        protection_profile_detail=proplists:get_value(ProtectionProfile, ?PROTECTION_PROFILE_DETAILS),
        mki = <<>> },

    % io:format("Using cipher suite ~120p", [ssl_cipher:suite_definition(CipherSuite)]),

    {ok, Tref} = timer:apply_after(1000, ?MODULE, retrans_timer_expired, [self()]),
    State1 = State0#state{
        msg_seq_r = MsgSeqR + 1,
        srtp_params = SrtpParams,
        hashsign_algorithm=HashsignAlgorithm,
        key_algorithm=KeyAlgorithm,
        premaster_secret=PremasterSecret,
        tmr = Tref,
        tmrV = 1,
        connection_states=CS1,
        tls_handshake_history = HS1},
    {next_state, certify_srv, server_certify_and_key_exchange(CipherSuite, State1)};

hello_srv({received_peer_record, #dtls_record{} = R}, #state{msg_seq_r = MsgSeqR}=St) ->
    io:format("receieved unexpected record ~160P at state[~p:~w].~n", [R, 50, hello_srv, MsgSeqR]),
    {next_state, hello_srv, St}.




-spec certify({received_peer_record, #dtls_record{}},
	    #state{}) -> gen_fsm_state_return(). 

certify({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?CERTIFICATE, message_seq=MsgSeqR} = CertificateRecord}, 
      #state{role = client, msg_seq_r = MsgSeqR} = State0) ->
    {next_state, certify, handle_peer_certificate(CertificateRecord, State0)};

certify({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?SERVER_KEY_EXCHANGE, content_raw=Raw, message_seq=MsgSeqR, fragment=ServerKeyChange}}, 
      #state{role = client, msg_seq_r = MsgSeqR, key_algorithm = KeyAlg, tls_handshake_history=HS0} = State0) ->
    #server_key_exchange{exchange_keys = Keys} = dtls4srtp_handshake:dec_hs(?SERVER_KEY_EXCHANGE, ServerKeyChange),
    State00 = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    Params = ssl_handshake:decode_server_key(Keys, KeyAlg, {3, 3}),
    HashSign = connection_hashsign(Params#server_key_params.hashsign, State0),
    State1 = 
        case HashSign of
            {_, SignAlgo} when SignAlgo == anon; SignAlgo == ecdh_anon ->
                server_master_secret(Params#server_key_params.params, State00);
            _ ->
                verify_server_key(Params, HashSign, State00)
        end,
    {next_state, certify, State1#state{msg_seq_r=MsgSeqR+1}};

certify({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?CERTIFICATE_REQUEST, content_raw=Raw, message_seq=MsgSeqR, fragment=CertificateRequest}}, 
      #state{role = client, msg_seq_r = MsgSeqR, tls_handshake_history=HS0} = State0) ->
    #certificate_request{} = dtls4srtp_handshake:dec_hs(?CERTIFICATE_REQUEST, CertificateRequest), 
    State = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    {next_state, certify, State#state{msg_seq_r=MsgSeqR+1}};

certify({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?SERVER_HELLO_DONE, content_raw=Raw, message_seq=MsgSeqR, fragment=ServerHelloDone}}, 
      #state{session = #session{master_secret = MasterSecret} = Session,
	       connection_states = ConnectionStates0,
	       premaster_secret = undefined,
	       role = client,
               tls_handshake_history=HS0} = State0) ->
    #server_hello_done{} = dtls4srtp_handshake:dec_hs(?SERVER_HELLO_DONE, ServerHelloDone),
    State00 = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    
    {MasterSecret, ConnectionStates} = ssl_handshake:master_secret(dtls_record, {3, 3}, Session, ConnectionStates0, client),
    % io:format("MasterSecret from session:~p~nSession:~p~nConnectionStates0:~p~n", [MasterSecret, Session, ConnectionStates0]),
    State1 = State00#state{connection_states = ConnectionStates},
    State = client_certify_and_key_exchange(State1),
    {next_state, cipher, State#state{msg_seq_r=MsgSeqR+1}};
certify({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?SERVER_HELLO_DONE, content_raw=Raw, message_seq=MsgSeqR, fragment=ServerHelloDone}}, 
      #state{session = Session0,
	       connection_states = ConnectionStates0,
	       premaster_secret = PremasterSecret,
	       role = client,
               tls_handshake_history = HS0} = State0) ->    
    #server_hello_done{} = dtls4srtp_handshake:dec_hs(?SERVER_HELLO_DONE, ServerHelloDone),
    State00 = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    {MasterSecret, ConnectionStates} = ssl_handshake:master_secret(dtls_record, {3, 3}, PremasterSecret, ConnectionStates0, client),
    Session = Session0#session{master_secret = MasterSecret},
    % io:format("MasterSecret from premaster:~p~nSession:~p~nConnectionStates0:~p~n", [MasterSecret, Session, ConnectionStates0]),
    State1 = State00#state{connection_states = ConnectionStates, session = Session},
    State = client_certify_and_key_exchange(State1),
    {next_state, cipher, State#state{msg_seq_r=MsgSeqR+1}};

certify({received_peer_record, #dtls_record{}}, #state{}=St) ->
    io:format("receieved unexpected record at state[~p].~n", [certify]),
    {next_state, certify, St}.



-spec certify_srv({received_peer_record, #dtls_record{}},
    #state{}) -> gen_fsm_state_return(). 

certify_srv({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?CERTIFICATE, message_seq=MsgSeqR} = CertificateRecord}, 
      #state{role = server, msg_seq_r = MsgSeqR} = State0) ->
    {next_state, certify_srv, handle_peer_certificate(CertificateRecord, State0)};

certify_srv({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?CLIENT_KEY_EXCHANGE, content_raw=Raw,
                message_seq=MsgSeqR, fragment=ClientKeyExchange}}, 
            #state{role = server, msg_seq_r = MsgSeqR, key_algorithm = KeyAlg, tls_handshake_history=HS0} = State0) ->
    #client_key_exchange{exchange_keys = Keys} = dtls4srtp_handshake:dec_hs(?CLIENT_KEY_EXCHANGE, ClientKeyExchange),
    State00 = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    Params = ssl_handshake:decode_client_key(Keys, KeyAlg, {3, 3}),
    State1 = certify_client_key_exchange(Params, State00),
    {next_state, cipher, State1#state{msg_seq_r=MsgSeqR+1}};

certify_srv({received_peer_record, #dtls_record{type = Type, content_type = ContentType, message_seq=MsgSeqR}}, #state{msg_seq_r = MsgSeqE}=St) ->
    io:format("receieved unexpected record type ~w/~w seq ~w (exp. ~w) at state[~p].~n", [Type, ContentType, MsgSeqR, MsgSeqE, certify_srv]),
    {next_state, certify_srv, St}.


certify_client_key_exchange(#client_diffie_hellman_public{dh_public = ClientPublicDhKey},
			    #state{diffie_hellman_params = #'DHParameter'{} = Params,
				   diffie_hellman_keys = {_, ServerDhPrivateKey}} = State) ->
    PremasterSecret = ssl_handshake:premaster_secret(ClientPublicDhKey, ServerDhPrivateKey, Params),
    master_from_premaster_secret(PremasterSecret, State);

certify_client_key_exchange(#client_ec_diffie_hellman_public{dh_public = ClientPublicEcDhPoint},
			    #state{diffie_hellman_keys = ECDHKey} = State) ->
    PremasterSecret = ssl_handshake:premaster_secret(#'ECPoint'{point = ClientPublicEcDhPoint}, ECDHKey),
    master_from_premaster_secret(PremasterSecret, State).


%% This part is common for peer certificate handling both in client and server certify state
handle_peer_certificate(#dtls_record{content_type=?CERTIFICATE, content_raw=Raw, message_seq=MsgSeqR, fragment=Certificate},
      #state{role = Role, msg_seq_r = MsgSeqR, session=Session, tls_handshake_history=HS0} = State0) ->

    #certificate{asn1_certificates = ASN1Certs} = dtls4srtp_handshake:dec_hs(?CERTIFICATE, Certificate),
    State00 = State0#state{tls_handshake_history=ssl_handshake:update_handshake_history(HS0, Raw)},
    [PeerCert | _] = ASN1Certs,
    case public_key:pkix_path_validation(selfsigned_peer, lists:reverse(ASN1Certs), [{max_path_length, 1}, {verify_fun, validate_fun_and_state(Role)}]) of
        {ok, {PublicKeyInfo,_}} ->
            State1 = State00#state{session = 
                Session#session{peer_certificate = PeerCert},
                public_key_info=PublicKeyInfo},
            % io:format("PublicKeyInfo (~w):~p~n", [Role, PublicKeyInfo]),
            State2 = case PublicKeyInfo of
                {?'id-ecPublicKey',  #'ECPoint'{point = _ECPoint} = PublicKey, PublicKeyParams} when Role == client ->
                    ECDHKey = public_key:generate_key(PublicKeyParams),
                    ec_dh_master_secret(ECDHKey, PublicKey, State1#state{diffie_hellman_keys=ECDHKey});
                _ ->
                    State1
            end,
            State2#state{msg_seq_r=MsgSeqR+1};
        {error, _Reason} ->
            io:format("Peer certificate validation failed.~n"),
            State00
    end.



-spec cipher({received_peer_record, #dtls_record{}},
	    #state{}) -> gen_fsm_state_return(). 

cipher({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?CERTIFICATE_VERIFY, content_raw=Raw, message_seq=MsgSeqR}}, 
      #state{role = server, msg_seq_r = MsgSeqR, tls_handshake_history = HS0} = State0) ->
    % io:format("Client certificate verify: ignore~n"),
    HS1 = ssl_handshake:update_handshake_history(HS0, Raw),
    {next_state, cipher, State0#state{msg_seq_r = MsgSeqR + 1, tls_handshake_history = HS1}};

cipher({received_peer_record, #dtls_record{type=?CHANGE_CIPHER_SPEC, content_raw=_Raw, fragment = <<1:8>>}}, 
      #state{connection_states = ConnectionStates0, role = client, tmr=Tmr} = State0) ->
    timer:cancel(Tmr),
    ConnectionStates1 = ssl_record:activate_pending_connection_state(ConnectionStates0, read),
    {next_state, cipher, State0#state{connection_states = ConnectionStates1}};

cipher({received_peer_record, #dtls_record{type=?CHANGE_CIPHER_SPEC, content_raw=_Raw, fragment = <<1:8>>}}, 
      #state{connection_states = ConnectionStates0, role = server, tmr=Tmr} = State0) ->
    timer:cancel(Tmr),
    ConnectionStates1 = ssl_record:activate_pending_connection_state(ConnectionStates0, read),
    {next_state, cipher, State0#state{connection_states = ConnectionStates1}};

cipher({received_peer_record, #dtls_record{type=?HANDSHAKE, content_type=?FINISHED, fragment=CipheredFrag}}, 
      #state{connection_states = ConnectionStates0,
               tls_handshake_history = Handshake0,
               session = #session{master_secret = MasterSecret},
	       role = Role,
               srtp_params=SrtpParams,
               owner=Owner} = State0) ->
    {PlainFrag, ConnStates} = dtls4srtp_record:decipher_dtls_record(CipheredFrag, ConnectionStates0),
    <<?FINISHED:8, _PlLen:24, _MsgSeq:16, _FragOffset:24, FragLen:24, VerifyData:(FragLen)/binary>> = PlainFrag,
    Handshake1 = ssl_handshake:update_handshake_history(Handshake0, PlainFrag),
    Finished = #finished{verify_data = VerifyData},
    true = is_binary(MasterSecret),
    %Role == client andalso io:format("Client got finished on handshake:~n   ~160P~n", [element(1, Handshake1), 50]),
    %Role == server andalso io:format("Server got PlainFrag ~160p~n", [PlainFrag]),
    verified = ssl_handshake:verify_connection({3, 3}, Finished, 
					 opposite_role(Role), 
					 get_current_connection_state_prf(ConnStates, read),
					 MasterSecret, Handshake1),
    %Session = register_session(Role, "Host", "Port", Session0),
    ConnectionStates1 = ssl_record:set_server_verify_data(current_both, VerifyData, ConnStates),
    NewSrtpParams = gen_srtp_key_material(ConnectionStates1, SrtpParams),
    % io:format("~w got key material~n", [Role]),
    Owner ! {dtls, key_material, NewSrtpParams},

    State1 = State0#state{connection_states = ConnectionStates1,
        tls_handshake_history = Handshake1,
        premaster_secret = undefined,
        srtp_params = NewSrtpParams},
    State2 = case Role of
        client -> State1;
        server -> server_finish_handshake(State1)
    end,
    State3 = State2#state{
                public_key_info = undefined,
                tls_handshake_history = ssl_handshake:init_handshake_history()},
    {next_state, connection, State3};

cipher({received_peer_record, #dtls_record{type = Type, content_type = ContentType, message_seq=MsgSeqR}}, #state{msg_seq_r = MsgSeqE}=St) ->
    io:format("receieved unexpected record type ~w/~w seq ~w (exp. ~w) at state[~p].~n", [Type, ContentType, MsgSeqR, MsgSeqE, cipher]),
    {next_state, cipher, St}.


connection(_Event, St) -> {next_state, connection, St}. 


%% problem remainning: different strategy should be adopted while state==hello_clt or cipher.
handle_event(retrans_timer_expired, StateName, #state{owner=Owner, seq_no=FSeqNo, flight_begin_epoch=Epoch, flight_begin_seq_no=SeqNo, flight_begin_cs=CS0, tmrV=TmrV,
			flights_tosend=Flight}=State0) ->
    {NewEpoch, NextTryBeginSeqNo, Bin} = dtls4srtp_record:encode_flight(Epoch, SeqNo, CS0, Flight),
    Owner ! {dtls, flight, Bin},
    NewTmrV = update_timer_value(TmrV),
    {ok, Tref} = timer:apply_after(NewTmrV*1000, ?MODULE, retrans_timer_expired, [self()]),
    State1 = State0#state{flight_begin_seq_no = NextTryBeginSeqNo,
                          seq_no = if NewEpoch == Epoch -> NextTryBeginSeqNo; true -> FSeqNo end,
                          tmr = Tref,
                          tmrV = NewTmrV},
    {next_state, StateName, State1};

handle_event({set_owner, OwnerPid}, StateName, #state{}=St) ->
    {next_state, StateName, St#state{owner=OwnerPid}};

handle_event({peer_cert_fingerprint, FingerP}, StateName, #state{}=St) ->
    {next_state, StateName, St#state{peer_cert_fingerprint=FingerP}};

handle_event(errordown, _, #state{}=St) -> 
    {stop, {shutdown, error}, St};
handle_event(shutdown, _, #state{}=St) -> 
    {stop, {shutdown, normal}, St}.

handle_sync_event(expect2receive, _, StateName, #state{msg_seq_r=MsgSeqR}=St) ->
    {reply,MsgSeqR,StateName,St};
handle_sync_event(self_cert_fingerprint, _, StateName, #state{self_cert_fingerprint=SCFP}=St) ->
    {reply,SCFP,StateName,St}.

handle_info({'DOWN', _, process, Owner, _}, _, #state{owner = Owner} = St) ->
    {stop, {shutdown, owner_dead}, St};
handle_info({'DOWN', _, _, Object, Reason}, _, #state{} = St) ->
    {stop, {shutdown, {something_has_died, Object, Reason}}, St};
handle_info(_Info, StateName, StateData) -> 
    {next_state, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
    ok.

code_change(_OldVsn, StateName, StateData, _Extra) -> 
    {ok, StateName, StateData}.

%% internal functions.
initial_state(Role, Owner, PeerCertFingerP) ->
    ConnectionStates = init_connection_states(Role),
    #state{session = #session{is_resumable = new},
	   role = Role,
           owner = Owner,
           peer_cert_fingerprint = PeerCertFingerP,
	   connection_states = ConnectionStates
	  }.

init_connection_states(Role) ->
    case proplists:get_value(init_connection_states, ssl_record:module_info(exports)) of
        1 -> ssl_record:init_connection_states(Role);
        2 -> ssl_record:init_connection_states(Role, disabled)
    end.

make_fingerprint({HashAlgo, _}, Cert) ->
    {HashAlgo, crypto:hash(HashAlgo, Cert)}.

make_secure_identities(Role, _, generate) ->
    % io:format("Generating one-time key and certificate...~n"),
    PrivateKey = webrtc_cert:gen_key(),
    OwnCert = webrtc_cert:create_cert(PrivateKey),
    init_manager_name(false),
    ClrCache = {ssl_crl_cache, {internal, []}},
    {ok, CertDbRef, CertDbHandle, FileRefHandle, _, CacheHandle, _} = ssl_manager:connection_init(<<>>, Role, ClrCache),
    {ok, CertDbRef, CertDbHandle, FileRefHandle, CacheHandle, OwnCert, PrivateKey, undefined};

make_secure_identities(Role, CertFile, KeyFile) ->
    init_manager_name(false),
    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, OwnCert} = init_certificates(Role, CertFile),
    PrivateKey = init_private_key(PemCacheHandle, KeyFile),
    {ok, CertDbRef, CertDbHandle, FileRefHandle, CacheHandle, OwnCert, PrivateKey, undefined}.

init_manager_name(false) ->
    put(ssl_manager, ssl_manager).

init_certificates(Role, CertFile) ->
    ClrCache = {ssl_crl_cache, {internal, []}},
    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, CRLDbInfo} = ssl_manager:connection_init(<<>>, Role, ClrCache),
    init_certificates(CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, CertFile, Role, CRLDbInfo).

init_certificates(CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, CertFile, _, _CRLDbInfo) ->
    [OwnCert|_] = ssl_certificate:file_to_certificats(CertFile, PemCacheHandle),
    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, OwnCert}.

init_private_key(DbHandle, KeyFile) ->
    {ok, List} = ssl_manager:cache_pem_file(KeyFile, DbHandle),
    [PemEntry] = [PemEntry || PemEntry = {PKey, _ , _} <- List,
			  PKey =:= 'RSAPrivateKey' orelse
			      PKey =:= 'DSAPrivateKey' orelse
			      PKey =:= 'ECPrivateKey' orelse
			      PKey =:= 'PrivateKeyInfo'
	     ],
    private_key(public_key:pem_entry_decode(PemEntry)).

private_key(#'PrivateKeyInfo'{privateKeyAlgorithm =
				 #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'rsaEncryption'},
			     privateKey = Key}) ->
    public_key:der_decode('RSAPrivateKey', iolist_to_binary(Key));

private_key(#'PrivateKeyInfo'{privateKeyAlgorithm =
				 #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'id-dsa'},
			     privateKey = Key}) ->
    public_key:der_decode('DSAPrivateKey', iolist_to_binary(Key));

private_key(Key) ->
    Key.

signature_types(CertBin) ->
    #'Certificate'{signatureAlgorithm=#'AlgorithmIdentifier'{algorithm=Algo}} = public_key:pem_entry_decode({'Certificate', CertBin, not_encrypted}),
    {_DigestType, _SignatureType} = public_key:pkix_sign_types(Algo).

hello_pending_connection_states(Role, Version, CipherSuite, Random, Compression,
				 ConnectionStates) ->    
    ReadState =  
	ssl_record:pending_connection_state(ConnectionStates, read),
    WriteState = 
	ssl_record:pending_connection_state(ConnectionStates, write),
    
    NewReadSecParams = 
	hello_security_parameters(Role, Version, ReadState, CipherSuite,
			    Random, Compression),
    
    NewWriteSecParams =
	hello_security_parameters(Role, Version, WriteState, CipherSuite,
			    Random, Compression),
 
    ssl_record:set_security_params(NewReadSecParams,
				    NewWriteSecParams,
				    ConnectionStates).

%% Handle server hello on client side
hello_security_parameters(client, Version, ConnectionState, CipherSuite, Random,
			  Compression) ->   
    SecParams = ConnectionState#connection_state.security_parameters,
    NewSecParams = ssl_cipher:security_parameters(Version, CipherSuite, SecParams),
    NewSecParams#security_parameters{
      server_random = Random,
      compression_algorithm = Compression
     };

%% Handle client hello on server side
hello_security_parameters(server, Version, ConnectionState, CipherSuite, Random,
			  Compression) ->   
    SecParams = ConnectionState#connection_state.security_parameters,
    NewSecParams = ssl_cipher:security_parameters(Version, CipherSuite, SecParams),
    NewSecParams#security_parameters{
      client_random = Random,
      compression_algorithm = Compression
     }.


gen_srtp_key_material(_, undefined) ->
  undefined;
gen_srtp_key_material(ConnectionStates, #srtp_params{protection_profile_detail=#protection_profile_detail{cipher_key_length=KeyLen, cipher_salt_length=SaltLen}}=SrtpParams) ->
    ConnectionState = ssl_record:current_connection_state(ConnectionStates, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{master_secret = MasterSecret,
       client_random = ClientRandom,
       server_random = ServerRandom,
       prf_algorithm = PRFAlgo } = SecParams,
    true = is_binary(MasterSecret),
    {ok, PRF} = case proplists:get_value(prf, ssl_handshake:module_info(exports)) of
        6 -> ssl_handshake:prf({3,3}, PRFAlgo, MasterSecret, "EXTRACTOR-dtls_srtp", [ClientRandom, ServerRandom], (2*(KeyLen+SaltLen)) div 8);
        5 -> ssl_handshake:prf({3,3}, MasterSecret, "EXTRACTOR-dtls_srtp", [ClientRandom, ServerRandom], (2*(KeyLen+SaltLen)) div 8)
    end,
    <<ClntWrtMKey:KeyLen, SvrWrtMKey:KeyLen, ClntWrtSalt:SaltLen, SvrWrtSalt:SaltLen>> = PRF,
    % io:format("gen_srtp_key_material, KeyLen:~p,SaltLen:~p~nresult(~p):~p~n", [KeyLen, SaltLen, byte_size(PRF), PRF]),
    %SrtpParams.
    SrtpParams#srtp_params{client_write_SRTP_master_key= <<ClntWrtMKey:KeyLen>>,
                           server_write_SRTP_master_key= <<SvrWrtMKey:KeyLen>>,
                           client_write_SRTP_master_salt= <<ClntWrtSalt:SaltLen>>,
                           server_write_SRTP_master_salt= <<SvrWrtSalt:SaltLen>>}.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
update_timer_value(TmrV) when TmrV > 60 -> 1;
update_timer_value(TmrV) -> 2*TmrV.

make_premaster_secret({MajVer, MinVer}, rsa) ->
    Rand = ssl:random_bytes(48-2),
    <<?BYTE(MajVer), ?BYTE(MinVer), Rand/binary>>;
make_premaster_secret(_, _) ->
    undefined.

connection_hashsign(HashSign = {_, _}, _State) ->
    HashSign;
connection_hashsign(_, #state{hashsign_algorithm = HashSign}) ->
    HashSign.


verify_server_key(#server_key_params{params = Params,
		             params_bin = EncParams,
		             signature = Signature},
	           HashSign = {HashAlgo, _},
	           #state{public_key_info = PubKeyInfo,
			     connection_states = ConnectionStates} = State) ->
    ConnectionState = ssl_record:pending_connection_state(ConnectionStates, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams, 
    Hash = ssl_handshake:server_key_exchange_hash(HashAlgo,
						  <<ClientRandom/binary,
						    ServerRandom/binary,
						    EncParams/binary>>),
    case ssl_handshake:verify_signature({3, 3}, Hash, HashSign, Signature, PubKeyInfo) of
    %case true of
	true ->
	    server_master_secret(Params, State);
	false ->
	    io:format("verify_server_key failed.~n"),
	    State
    end.


server_master_secret(#server_dh_params{dh_p = P, dh_g = G, dh_y = ServerPublicDhKey},
         St) ->
    dh_master_secret(P, G, ServerPublicDhKey, undefined, St);

server_master_secret(#server_ecdh_params{curve = ECCurve, public = ECServerPubKey},
         St) ->
    ECDHKeys = public_key:generate_key(ECCurve),
    ec_dh_master_secret(ECDHKeys, #'ECPoint'{point = ECServerPubKey}, St#state{diffie_hellman_keys = ECDHKeys});

server_master_secret(#server_psk_params{
      hint = IdentityHint},
         St) ->
    %% store for later use
    St#state{psk_identity = IdentityHint}.


% dh_master_secret(#'DHParameter'{} = Params, OtherPublicDhKey, MyPrivateKey, St) ->
%     PremasterSecret = public_key:compute_key(OtherPublicDhKey, MyPrivateKey, Params),
%     master_from_premaster_secret(PremasterSecret, St).

dh_master_secret(Prime, Base, PublicDhKey, undefined, St) ->
    Keys = {_, PrivateDhKey} = crypto:generate_key(dh, [Prime, Base]),
    dh_master_secret(Prime, Base, PublicDhKey, PrivateDhKey, St#state{diffie_hellman_keys = Keys});

dh_master_secret(Prime, Base, PublicDhKey, PrivateDhKey, St) ->
    PremasterSecret = crypto:compute_key(dh, PublicDhKey, PrivateDhKey, [Prime, Base]),
    master_from_premaster_secret(PremasterSecret, St).


ec_dh_master_secret(ECDHKeys, ECPoint, St) ->
    PremasterSecret = public_key:compute_key(ECPoint, ECDHKeys),
    master_from_premaster_secret(PremasterSecret, St).


%% RFC 5246, Sect. 7.4.1.4.1.  Signature Algorithms
%% If the client does not send the signature_algorithms extension, the
%% server MUST do the following:
%%
%% -  If the negotiated key exchange algorithm is one of (RSA, DHE_RSA,
%%    DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA), behave as if client had
%%    sent the value {sha1,rsa}.
%%
%% -  If the negotiated key exchange algorithm is one of (DHE_DSS,
%%    DH_DSS), behave as if the client had sent the value {sha1,dsa}.
%%
%% -  If the negotiated key exchange algorithm is one of (ECDH_ECDSA,
%%    ECDHE_ECDSA), behave as if the client had sent value {sha1,ecdsa}.

default_hashsign({16#fe, _}, KeyExchange) ->
    default_hashsign({3, 3}, KeyExchange);
default_hashsign(_Version = {Major, Minor}, KeyExchange)
  when Major == 3 andalso Minor >= 3 andalso
       (KeyExchange == rsa orelse
  KeyExchange == dhe_rsa orelse
  KeyExchange == dh_rsa orelse
  KeyExchange == ecdhe_rsa orelse
  KeyExchange == srp_rsa) ->
    {sha, rsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == rsa;
       KeyExchange == dhe_rsa;
       KeyExchange == dh_rsa;
       KeyExchange == ecdhe_rsa;
       KeyExchange == srp_rsa ->
    {md5sha, rsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == ecdhe_ecdsa;
       KeyExchange == ecdh_ecdsa;
       KeyExchange == ecdh_rsa ->
    {sha, ecdsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == dhe_dss;
       KeyExchange == dh_dss;
       KeyExchange == srp_dss ->
    {sha, dsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == dh_anon;
       KeyExchange == ecdh_anon;
       KeyExchange == psk;
       KeyExchange == dhe_psk;
       KeyExchange == rsa_psk;
       KeyExchange == srp_anon ->
    {null, anon}.

validate_fun_and_state(Role) ->
   {fun(_OtpCert, _ExtensionOrVerifyResult, _SslState) ->
       {valid, Role}
     end, Role}.


master_from_premaster_secret(PremasterSecret,
			     #state{session = Session,
				    role = Role,
				    connection_states = ConnectionStates0} = State) when is_binary(PremasterSecret) ->
    {MasterSecret, ConnectionStates} = ssl_handshake:master_secret(dtls_record, {3, 3}, PremasterSecret,
				     ConnectionStates0, Role),
    % io:format("master_from_premaster_secret ~160p~n      -> ~160p~n    << ~160p~n", [PremasterSecret, MasterSecret, process_info(self(), current_stacktrace)]),
    State#state{session = Session#session{master_secret = MasterSecret},
	        connection_states = ConnectionStates}.

client_certify_and_key_exchange(#state{epoch=Epoch, owner=Owner, connection_states=CS0} = State0) ->
    % State1 = State0, Bin1 = <<>>,
    {State1, ClientCertificate, Bin1} = certificate(State0),
    {State2, ClientKeyExchange, Bin2} = key_exchange(State1),
    % State3 = State2, Bin3 = <<>>,
    {State3, CertificateVerify, Bin3} = verify_client_cert(State2),
    % State4 = State3, Bin4 = <<>>,
    {State4, CipherSpec, Bin4} = cipher_protocol(State3),
    % State5 = State4, Bin5 = <<>>,
    {State5, Finish, Bin5} = finished(State4),

    Flight = [{?HANDSHAKE, ClientCertificate}
               , {?HANDSHAKE, ClientKeyExchange}
               , {?HANDSHAKE, CertificateVerify}
               , {?CHANGE_CIPHER_SPEC, CipherSpec}
               , {?HANDSHAKE, Finish}
               ],
    Bin = iolist_to_binary([Bin1, Bin2, Bin3, Bin4, Bin5]),
    Owner ! {dtls, flight, Bin},
    %{ok, Tref} = timer:apply_after(5000, ?MODULE, retrans_timer_expired, [self()]),
    State5#state{%tmr = Tref,
                 tmrV = 5,
                 flight_begin_epoch = Epoch,
                 flight_begin_seq_no = State0#state.seq_no,
                 flight_begin_cs = CS0,
                 flights_tosend = Flight}.


server_certify_and_key_exchange(CipherSuite, #state{epoch=Epoch, owner=Owner, connection_states=CS0} = State0) ->

    {State1, ServerHello, Bin1} = server_hello(CipherSuite, State0),
    % State2 = State1, Bin2 = <<>>,
    {State2, Certificate, Bin2} = certificate(State1),
    % State3 = State2, Bin3 = <<>>,
    {State3, ServerKeyExchange, Bin3} = key_exchange(State2),
    % State4 = State3, Bin4 = <<>>,
    {State4, CertRequest, Bin4} = request_client_cert(State3),
    %% TODO: server_hello_done
    % State5 = State4, Bin5 = <<>>,
    {State5, ServerHelloDone, Bin5} = server_hello_done(State4),


    Flight = [{?HANDSHAKE, ServerHello}
            , {?HANDSHAKE, Certificate}
            , {?HANDSHAKE, ServerKeyExchange}
            , {?HANDSHAKE, CertRequest}
            , {?HANDSHAKE, ServerHelloDone}
             ],
    Bin = iolist_to_binary([Bin1, Bin2, Bin3, Bin4, Bin5]),
    Owner ! {dtls, flight, Bin},
    %{ok, Tref} = timer:apply_after(5000, ?MODULE, retrans_timer_expired, [self()]),
    State5#state{%tmr = Tref,
                 tmrV = 5,
                 flight_begin_epoch = Epoch,
                 flight_begin_seq_no = State0#state.seq_no,
                 flight_begin_cs = CS0,
                 flights_tosend = Flight}.


server_finish_handshake(#state{epoch=Epoch, owner=Owner, connection_states=CS0} = State0) ->
    {State1, CipherSpec, Bin1} = cipher_protocol(State0),
    {State2, Finish, Bin2} = finished(State1),

    Flight = [{?CHANGE_CIPHER_SPEC, CipherSpec}
            , {?HANDSHAKE, Finish}
             ],
    Bin = iolist_to_binary([Bin1, Bin2]),
    Owner ! {dtls, flight, Bin},
    State2#state{
                 tmrV = 2,
                 flight_begin_epoch = Epoch,
                 flight_begin_seq_no = State0#state.seq_no,
                 flight_begin_cs = CS0,
                 flights_tosend = Flight}.


certificate(#state{role = Role,
                      epoch = Epoch,
                      seq_no = SeqNo,
                      connection_states = ConnectionStates0,
		      cert_db = CertDbHandle,
                      cert_db_ref = CertDbRef,
		      session = #session{own_certificate = OwnCert},
                      tls_handshake_history = Handshake0,
                      msg_seq_s=MsgSeqS} = State) ->
    Certificate = ssl_handshake:certificate(OwnCert, CertDbHandle, CertDbRef, Role),
    {BinCert, Frag, ConnectionStates, Handshake} =
        encode_handshake(Certificate, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                 connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinCert}.

key_exchange(#state{role = server, key_algorithm = Algo,
		    hashsign_algorithm = HashSignAlgo,
		    diffie_hellman_params = #'DHParameter'{} = Params,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
            epoch = Epoch, seq_no = SeqNo, msg_seq_s = MsgSeqS, tls_handshake_history = Handshake0
		   } = State0)
  when Algo == dhe_dss;
       Algo == dhe_rsa;
       Algo == dh_anon ->
    DHKeys = public_key:generate_key(Params),
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg = ssl_handshake:key_exchange(server, {3, 3}, {dh, DHKeys, Params,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),

    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),

    {State0#state{diffie_hellman_keys = DHKeys, msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg};

key_exchange(#state{role = server, private_key = Key, key_algorithm = Algo} = State)
when Algo == ecdh_ecdsa; Algo == ecdh_rsa ->
    {State#state{diffie_hellman_keys = Key}, undefined, <<>>};

key_exchange(#state{role = server, key_algorithm = Algo,
		    hashsign_algorithm = HashSignAlgo,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
            epoch = Epoch, seq_no = SeqNo, msg_seq_s = MsgSeqS, tls_handshake_history = Handshake0
		   } = State0)
  when Algo == ecdhe_ecdsa; Algo == ecdhe_rsa;
       Algo == ecdh_anon ->

    ECDHKeys = public_key:generate_key({namedCurve, ?secp256r1}), % (select_curve(State0)),
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, {3, 3}, {ecdh, ECDHKeys,
							HashSignAlgo, ClientRandom,
							ServerRandom,
							PrivateKey}),

    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State0#state{diffie_hellman_keys = ECDHKeys, msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg};


key_exchange(#state{role = client, 
		    epoch = Epoch,
                    seq_no = SeqNo,
                    connection_states = ConnectionStates0,
		    key_algorithm = rsa,
		    public_key_info = PublicKeyInfo,
		    premaster_secret = PremasterSecret,
		    tls_handshake_history = Handshake0,
                      msg_seq_s=MsgSeqS} = State) ->
    Msg = rsa_key_exchange(PremasterSecret, PublicKeyInfo),
    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg};
key_exchange(#state{role = client, 
                    epoch = Epoch,
                    seq_no = SeqNo,
                    connection_states = ConnectionStates0,
		    key_algorithm = Algorithm,
		    diffie_hellman_keys = {DhPubKey, _},
		    tls_handshake_history = Handshake0,
                      msg_seq_s=MsgSeqS} = State)
  when Algorithm == dhe_dss;
       Algorithm == dhe_rsa;
       Algorithm == dh_anon ->
    Msg =  ssl_handshake:key_exchange(client, {3, 3}, {dh, DhPubKey}),
    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg};

key_exchange(#state{role = client,
                    epoch = Epoch,
                    seq_no = SeqNo,
                    connection_states = ConnectionStates0,
		    key_algorithm = Algorithm,
		    diffie_hellman_keys = Keys,
		    tls_handshake_history = Handshake0,
                      msg_seq_s=MsgSeqS} = State)
  when Algorithm == ecdhe_ecdsa; Algorithm == ecdhe_rsa;
       Algorithm == ecdh_ecdsa; Algorithm == ecdh_rsa;
       Algorithm == ecdh_anon ->
    Msg = ssl_handshake:key_exchange(client, {3, 3}, {ecdh, Keys}),
    % io:format("key_exchange ~w, Keys:~p~nMsg:~p~n", [Algorithm, Keys, Msg]),
    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg}.

rsa_key_exchange(PremasterSecret, PublicKeyInfo = {Algorithm, _, _})
  when Algorithm == ?rsaEncryption;
       Algorithm == ?md2WithRSAEncryption;
       Algorithm == ?md5WithRSAEncryption;
       Algorithm == ?sha1WithRSAEncryption;
       Algorithm == ?sha224WithRSAEncryption;
       Algorithm == ?sha256WithRSAEncryption;
       Algorithm == ?sha384WithRSAEncryption;
       Algorithm == ?sha512WithRSAEncryption
       ->
    ssl_handshake:key_exchange(client, {3, 3},
			       {premaster_secret, PremasterSecret,
				PublicKeyInfo}).

request_client_cert(#state{
			   connection_states = ConnectionStates0,
			   cert_db = CertDbHandle,
			   cert_db_ref = CertDbRef,
               hashsign_algorithm = HashsignAlgorithm,
            epoch = Epoch, seq_no = SeqNo, msg_seq_s = MsgSeqS, tls_handshake_history = Handshake0
           } = State0) ->
    #connection_state{security_parameters =
			  #security_parameters{cipher_suite = CipherSuite}} =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    HashSigns = #hash_sign_algos{hash_sign_algos = [HashsignAlgorithm]},
    Msg = case proplists:get_value(certificate_request, ssl_handshake:module_info(exports)) of
        4 -> ssl_handshake:certificate_request(CipherSuite, CertDbHandle, CertDbRef, {3, 3});
        5 -> ssl_handshake:certificate_request(CipherSuite, CertDbHandle, CertDbRef, HashSigns, {3, 3})
    end,

    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State0#state{client_certificate_requested = true, msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg}.


verify_client_cert(#state{role = client,
                          epoch = Epoch,
                          seq_no = SeqNo,
                          connection_states = ConnectionStates0,
			  private_key = PrivateKey,
			  session = #session{master_secret = MasterSecret,
					     own_certificate = OwnCert},
        key_algorithm = _KeyAlgorithm,
			  signature_types = HashSign,
			  tls_handshake_history = Handshake0,
			  msg_seq_s=MsgSeqS} = State) ->

    % io:format("KeyAlgorithm:~p,HashSign:~p~nPrivateKey:~p~n,Handshake0:~p~n", [_KeyAlgorithm, HashSign, PrivateKey, Handshake0]),
    #certificate_verify{} = Verified = ssl_handshake:client_certificate_verify(OwnCert, MasterSecret, 
						 {3, 3}, HashSign, PrivateKey, Handshake0),
    {BinVerified, Frag, ConnectionStates, Handshake} = 
        encode_handshake(Verified, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    % io:format("CertificateVerify:~p~n",[Verified]),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinVerified}.

cipher_protocol(#state{epoch = Epoch,
                       seq_no = SeqNo,
                       connection_states = ConnectionStates0}=State) ->
    {BinChangeCipher, ConnectionStates1} =
        encode_change_cipher(#change_cipher_spec{}, ConnectionStates0, Epoch, SeqNo),
    ConnectionStates = ssl_record:activate_pending_connection_state(ConnectionStates1, write),
    {State#state{connection_states=ConnectionStates, epoch=Epoch+1, seq_no=0}, <<1:8>>, BinChangeCipher}.
   
finished(#state{role = Role,
		session = Session,
                epoch = Epoch,
                seq_no = SeqNo,
                connection_states = ConnectionStates0,
                tls_handshake_history = Handshake0,
                msg_seq_s=MsgSeqS}=State) ->
    MasterSecret = Session#session.master_secret,
    Finished = ssl_handshake:finished({3, 3}, Role,
				       get_current_connection_state_prf(ConnectionStates0, write),
				       MasterSecret, Handshake0),
    %Role == server andalso io:format("Server sending finished on handshake:~n   ~160P~n", [element(1, Handshake0), 50]),
    %Finished = #finished{verify_data=ssl:random_bytes(12)},
    ConnectionStates1 = save_verify_data(Role, Finished, ConnectionStates0),
    {BinFinished, Frag, ConnectionStates, Handshake} =
        encode_handshake(Finished, MsgSeqS, ConnectionStates1, Handshake0, Epoch, SeqNo),
    %Role == client andalso io:format("Client finished frag: ~160p~n", [Frag]),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinFinished}.


server_hello(CipherSuite, #state{epoch = Epoch,
                       seq_no = SeqNo,
                       msg_seq_s=MsgSeqS,
                       tls_handshake_history = Handshake0,
                       connection_states = ConnectionStates0}=State) ->
    SessionID = crypto:strong_rand_bytes(32),
    Pending = ssl_record:pending_connection_state(ConnectionStates0, read),
    #security_parameters{server_random = ServerRandom} = Pending#connection_state.security_parameters,

    ServerHello = dtls4srtp_handshake:server_hello(MsgSeqS, ServerRandom, SessionID, CipherSuite),

    % current mood: i_have_no_idea_what_am_i_doing.jpg
    Handshake = ssl_handshake:update_handshake_history(Handshake0, ServerHello),
    {ServerHelloBin, ConnectionStates} = dtls4srtp_record:encode_handshake(ServerHello, ConnectionStates0, Epoch, SeqNo),

    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                 connection_states=ConnectionStates, seq_no=SeqNo+1}, ServerHello, ServerHelloBin}.


server_hello_done(#state{epoch = Epoch, seq_no = SeqNo, msg_seq_s = MsgSeqS,
                tls_handshake_history = Handshake0, connection_states = ConnectionStates0} = State) ->
    Msg = ssl_handshake:server_hello_done(),
    {BinMsg, Frag, ConnectionStates, Handshake} =
        encode_handshake(Msg, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo),
    {State#state{msg_seq_s=MsgSeqS+1, tls_handshake_history=Handshake,
                connection_states=ConnectionStates, seq_no=SeqNo+1}, Frag, BinMsg}.

   
save_verify_data(client, #finished{verify_data = Data}, ConnectionStates) ->
    ssl_record:set_client_verify_data(current_write, Data, ConnectionStates);
save_verify_data(server, #finished{verify_data = Data}, ConnectionStates) ->
    ssl_record:set_server_verify_data(current_both, Data, ConnectionStates).

get_current_connection_state_prf(CStates, Direction) ->
	CS = ssl_record:current_connection_state(CStates, Direction),
	CS#connection_state.security_parameters#security_parameters.prf_algorithm.

% register_session(client, _Host, _Port, #session{is_resumable = new} = Session0) ->
%     Session = Session0#session{is_resumable = true},
%     %%ssl_manager:register_session(Host, Port, Session),
%     Session.

%%%%%%%
encode_change_cipher(#change_cipher_spec{}, ConnectionStates, Epoch, SeqNo) ->
    dtls4srtp_record:encode_change_cipher_spec(ConnectionStates, Epoch, SeqNo).

encode_handshake(HandshakeRec, MsgSeqS, ConnectionStates0, Handshake0, Epoch, SeqNo) ->
    Frag = dtls4srtp_handshake:encode_handshake(HandshakeRec, MsgSeqS),
    %io:format("Handshake0:~p, Frag:~p~n", [Handshake0, Frag]),
    Handshake1 = ssl_handshake:update_handshake_history(Handshake0, Frag),
    {E, ConnectionStates1} =
        dtls4srtp_record:encode_handshake(Frag, ConnectionStates0, Epoch, SeqNo),
    {E, Frag, ConnectionStates1, Handshake1}.

encode_client_hello(Frag, ConnectionStates0, Epoch, SeqNo) ->
    dtls4srtp_record:encode_handshake(Frag, ConnectionStates0, Epoch, SeqNo).


opposite_role(client) ->
    server;
opposite_role(server) ->
    client.

