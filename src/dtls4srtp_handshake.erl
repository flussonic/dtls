% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil -*-
-module(dtls4srtp_handshake).

-include_lib("ssl/src/ssl_internal.hrl").
-include("dtls4srtp_handshake.hrl").

-compile(export_all).


client_hello(MessageSeq, ClientRandom) -> client_hello(MessageSeq, ClientRandom, <<>>, <<>>).

client_hello(MessageSeq, ClientRandom, Cookie) -> client_hello(MessageSeq, ClientRandom, <<>>, Cookie).

client_hello(MessageSeq, ClientRandom, SessionID, Cookie) when is_binary(SessionID) andalso is_binary(Cookie) ->
    SessionIDBlock = case SessionID of 
                       <<>> -> <<0:8>>;
                       _ -> <<(size(SessionID)):8,SessionID/binary>> 
                   end,
    CookieIDBlock = case Cookie of 
                    <<>> -> <<0:8>>; 
                    _ -> <<(size(Cookie)):8,Cookie/binary>> 
                end,
    SupportedCipherSuites = supported_cipher_suites(),
    SupportedCompressionMethods = supported_compression_methods(),
    ExtRenegotiationInfo = extension_renegotiation_info(),
    %ExtEllipticCurves = extension_elliptic_curves(),
    %ExtEcPointFormats = extension_ec_point_formats(),
    ExtEcc = supported_ecc2(),
    ExtUseSrtp = extension_use_srtp(client),
    ExtensionsLength = size(ExtRenegotiationInfo) + size(ExtEcc) + size(ExtUseSrtp),
    ClientHelloContent = <<
               %16#feff:16,                  %% Version: DTLS 1.0 (0xfeff)
               16#fefd:16,                  %% Version: DTLS 1.2 (0xfefd)
               ClientRandom/binary,
               SessionIDBlock/binary,
               CookieIDBlock/binary,
               SupportedCipherSuites/binary,    
               SupportedCompressionMethods/binary,
               ExtensionsLength:16,               %% Extensions Length.
               ExtRenegotiationInfo/binary,
               %ExtEllipticCurves/binary,
               %ExtEcPointFormats/binary,
               ExtEcc/binary,
               ExtUseSrtp/binary
              >>,
    encode_client_hello(?CLIENT_HELLO, ClientHelloContent, MessageSeq).


server_hello(MessageSeq, ServerRandom, SessionID, CipherSuite) ->
    ExtRenegotiationInfo = extension_renegotiation_info(),
    ExtECPointFormats = extension_ec_point_formats(),
    ExtUseSRTP = extension_use_srtp(server),
    Extensions = <<ExtRenegotiationInfo/binary, ExtECPointFormats/binary, ExtUseSRTP/binary>>,
    ServerHelloContent = <<
        16#fefd:16,
        ServerRandom:32/binary,
        (byte_size(SessionID)):8, SessionID/binary,
        CipherSuite:2/binary,
        0, % No compression
        (byte_size(Extensions)):16, Extensions/binary>>,
    encode_client_hello(?SERVER_HELLO, ServerHelloContent, MessageSeq).

encode_client_hello(HandshakeType, HandshakeContent, MessageSeq) ->
    Len = byte_size(HandshakeContent),
    [HandshakeType, ?uint24(Len), ?uint16(MessageSeq), ?uint24(0), ?uint24(Len), HandshakeContent].

encode_handshake(Package, MessageSeq) ->
    [MsgType, ?uint24(Len), Bin] = tls_handshake:encode_handshake(Package, {3, 3}),
    [MsgType, ?uint24(Len), ?uint16(MessageSeq), ?uint24(0), ?uint24(Len), Bin].

certs_from_list(ACList) ->
    list_to_binary([begin
                        CertLen = byte_size(Cert),
                        <<?UINT24(CertLen), Cert/binary>>
                    end || Cert <- ACList]).

%%%%%%%%%%
supported_cipher_suites() ->  %% Cipher Suites (29 suites)
    % io:format("Cipher suites: ~160p~n", [[ssl_cipher:suite_definition(S) || S <- Suites]]),
    %Suites = ssl_cipher:suites({3,2}),
    %Suites = [<<?BYTE(16#00), ?BYTE(16#35)>>],
    BinSuites = list_to_binary(good_cipher_suites()),
    <<
      (size(BinSuites)):16,  %% Cipher Suites Length.
      BinSuites/binary
    >>.

choose_cipher_suite(CipherSuites) ->
    CommonSuites = lists:dropwhile(fun(S) -> not lists:member(S, CipherSuites) end, good_cipher_suites()),
    hd(CommonSuites).

good_cipher_suites() ->
    Suites0 = [S || S <- ssl_cipher:suites({3,3}), is_good_ciphersuite(ssl_cipher:suite_definition(S))],
    ssl_cipher:filter_suites(Suites0).

is_good_ciphersuite({_KeyExchange, Cipher, _Hash, _Prf}) ->
  % Some bulk ciphers are not supported by ssl_cipher:cipher/5
  not lists:member(Cipher, [aes_128_gcm, aes_256_gcm, chacha20_poly1305]).


supported_compression_methods() ->
    CM = ssl_record:compressions(),
    BinCM = list_to_binary(CM),
    <<
      (size(BinCM)):8,      %% Compression Methods Length
      BinCM/binary
    >>.


extension_renegotiation_info() ->
    <<
      16#ff01:16,              %% Type: renegotiation_info (0xff01)
      16#0001:16,              %% Length: 1
      16#00:8                  %% Data (1 byte)
    >>.

supported_ecc() ->
    CipherSuites = ssl_cipher:suites({3,3}),
    {EcPointFormats, EllipticCurves} = default_ecc_extensions({3,3}),
    Extensions0 = ec_hello_extensions(lists:map(fun ssl_cipher:suite_definition/1, CipherSuites), EcPointFormats)
    ++ ec_hello_extensions(lists:map(fun ssl_cipher:suite_definition/1, CipherSuites), EllipticCurves),
    enc_hello_extensions(Extensions0).

default_ecc_extensions(Version) ->
    CryptoSupport = proplists:get_value(public_keys, crypto:supports()),
    case proplists:get_bool(ecdh, CryptoSupport) of
      true ->
          EcPointFormats = #ec_point_formats{ec_point_format_list = [?ECPOINT_UNCOMPRESSED]},
          EllipticCurves = #elliptic_curves{elliptic_curve_list = tls_v1:ecc_curves(Version)},
          {EcPointFormats, EllipticCurves};
      _ ->
          {undefined, undefined}
    end.

ec_hello_extensions(CipherSuites, #elliptic_curves{} = Info) ->
    case advertises_ec_ciphers(CipherSuites) of
    true ->
        [Info];
    false ->
        []
    end;
ec_hello_extensions(CipherSuites, #ec_point_formats{} = Info) ->
    case advertises_ec_ciphers(CipherSuites) of
    true ->
        [Info];
    false ->
        []
    end;
ec_hello_extensions(_, undefined) ->
    [].


advertises_ec_ciphers([]) ->
    false;
advertises_ec_ciphers([{ecdh_ecdsa, _,_,_} | _]) ->
    true;
advertises_ec_ciphers([{ecdhe_ecdsa, _,_,_} | _]) ->
    true;
advertises_ec_ciphers([{ecdh_rsa, _,_,_} | _]) ->
    true;
advertises_ec_ciphers([{ecdhe_rsa, _,_,_} | _]) ->
    true;
advertises_ec_ciphers([{ecdh_anon, _,_,_} | _]) ->
    true;
advertises_ec_ciphers([_| Rest]) ->
    advertises_ec_ciphers(Rest).

enc_hello_extensions(Extensions) ->
    enc_hello_extensions(Extensions, <<>>).

enc_hello_extensions([], Acc) when is_binary(Acc) -> Acc;
enc_hello_extensions([#elliptic_curves{elliptic_curve_list = EllipticCurves} | Rest], Acc) ->
    EllipticCurveList = << <<(tls_v1:oid_to_enum(X)):16>> || X <- EllipticCurves>>,
    ListLen = byte_size(EllipticCurveList),
    Len = ListLen + 2,
    enc_hello_extensions(Rest, <<?UINT16(?ELLIPTIC_CURVES_EXT),
                 ?UINT16(Len), ?UINT16(ListLen), EllipticCurveList/binary, Acc/binary>>);
enc_hello_extensions([#ec_point_formats{ec_point_format_list = ECPointFormats} | Rest], Acc) ->
    ECPointFormatList = list_to_binary(ECPointFormats),
    ListLen = byte_size(ECPointFormatList),
    Len = ListLen + 1,
    enc_hello_extensions(Rest, <<?UINT16(?EC_POINT_FORMATS_EXT),
                 ?UINT16(Len), ?BYTE(ListLen), ECPointFormatList/binary, Acc/binary>>).

supported_ecc1() ->
    CryptoSupport = proplists:get_value(public_keys, crypto:supports()),
    case proplists:get_bool(ecdh, CryptoSupport) of
        true ->
            ECPointFormats = [?ECPOINT_UNCOMPRESSED],
            EllipticCurves = tls_v1:ecc_curves({3,3}),
            
            ECPointFormatList = list_to_binary(ECPointFormats),
            ListLen2 = byte_size(ECPointFormatList),
            Len2 = ListLen2 + 1,
            Bin2 = <<?UINT16(?EC_POINT_FORMATS_EXT), ?UINT16(Len2), ?BYTE(ListLen2), ECPointFormatList/binary>>,

            EllipticCurveList = << <<(tls_v1:oid_to_enum(X)):16>> || X <- EllipticCurves>>,
            ListLen1 = byte_size(EllipticCurveList),
            Len1 = ListLen1 + 2,
            <<?UINT16(?ELLIPTIC_CURVES_EXT), ?UINT16(Len1), ?UINT16(ListLen1), EllipticCurveList/binary, Bin2/binary>>;
        _ ->
            <<>>
    end.


supported_ecc2() ->
    <<
      16#000a:16,              %% Type: elliptic_curves (0x000a)
      16#0008:16,              %% Length: 8
      16#0006001700180019:64,  %% Data (8 bytes)
      16#000b:16,              %% Type: ec_point_formats (0x000b)
      16#0002:16,              %% Length: 2
      16#0100:16               %% Data (2 bytes)
    >>.

extension_elliptic_curves() ->
    <<
      16#000a:16,              %% Type: elliptic_curves (0x000a)
      16#0008:16,              %% Length: 8
      16#0006001700180019:64   %% Data (8 bytes)
    >>.

extension_ec_point_formats() ->
    <<
      16#000b:16,              %% Type: ec_point_formats (0x000b)
      16#0002:16,              %% Length: 2
      16#0100:16               %% Data (2 bytes)
    >>.

extension_use_srtp(client) ->
    Profiles = [
        <<0,1>>,               %% SRTP_AES128_CM_HMAC_SHA1_80
        %<<0,2>>],              %% SRTP_AES128_CM_HMAC_SHA1_32
        <<0,5>>],             %% SRTP_NULL_HMAC_SHA1_80
    Data = iolist_to_binary([<<(iolist_size(Profiles)):16>>, Profiles, <<0>>]), % No MKI

    <<
      16#000e:16,              %% Type: use_srtp (0x000e)
      (byte_size(Data)):16,    %% Length
      Data/binary
    >>;
extension_use_srtp(server) ->
    <<
      16#000e:16,              %% Type: use_srtp (0x000e)
      16#0005:16,              %% Length: 5
      16#0002000100:40         %% Data (5 bytes)
    >>.


%%% decode handshake packet.
dec_hs(?HELLO_VERIFY_REQUEST, <<?BYTE(Major), ?BYTE(Minor), 
           ?BYTE(CookieLen), Cookie:CookieLen/binary>>) ->
    #hello_verify_request{protocol_version={Major,Minor},
                          cookie=Cookie};

dec_hs(?SERVER_HELLO, <<?BYTE(Major), ?BYTE(Minor), Random:32/binary,
		       ?BYTE(SID_length), Session_ID:SID_length/binary,
		       Cipher_suite:2/binary, ?BYTE(Comp_method),
		       ?UINT16(ExtLen), Extensions:ExtLen/binary>>) ->
    
    HelloExtensions = dec_hello_extensions(Extensions, []),
    RenegotiationInfo = proplists:get_value(renegotiation_info, HelloExtensions,
					   undefined),
    HashSigns = proplists:get_value(hash_signs, HelloExtensions,
					   undefined),
    EllipticCurves = proplists:get_value(elliptic_curves, HelloExtensions,
					   undefined),
    UseSRTP = proplists:get_value(use_srtp, HelloExtensions),
    
    #dtls_server_hello{
	server_version = {Major,Minor},
	random = Random,
	session_id = Session_ID,
	cipher_suite = Cipher_suite,
	compression_method = Comp_method,
	renegotiation_info = RenegotiationInfo,
	hash_signs = HashSigns,
	elliptic_curves = EllipticCurves,
        use_srtp = UseSRTP};

dec_hs(?CLIENT_HELLO, <<?BYTE(Major), ?BYTE(Minor), Random:32/binary,
      ?BYTE(SID_length), Session_ID:SID_length/binary,
      ?BYTE(Cookie_length), Cookie:Cookie_length/binary,
      ?UINT16(Cs_length), CipherSuites:Cs_length/binary,
      ?BYTE(Cm_length), Comp_methods:Cm_length/binary,
      Extensions/binary>>) ->

      DecodedExtensions = ssl_handshake:decode_hello_extensions(Extensions),

      #dtls_client_hello{
        client_version = {Major,Minor},
        random = Random,
        session_id = Session_ID,
        cookie = Cookie,
        cipher_suites = ssl_handshake:decode_suites('2_bytes', CipherSuites),
        compression_methods = Comp_methods,
        extensions = DecodedExtensions
      };

dec_hs(?CERTIFICATE, <<?UINT24(ACLen), ASN1Certs:ACLen/binary>>) ->
    #certificate{asn1_certificates = certs_to_list(ASN1Certs)};
dec_hs(?SERVER_KEY_EXCHANGE, Keys) ->
    #server_key_exchange{exchange_keys = Keys};
dec_hs(?CLIENT_KEY_EXCHANGE, Keys) ->
    #client_key_exchange{exchange_keys = Keys};
dec_hs(?CERTIFICATE_REQUEST,
       <<?BYTE(CertTypesLen), CertTypes:CertTypesLen/binary,
	?UINT16(CertAuthsLen), CertAuths:CertAuthsLen/binary, _DistinguishedNames/binary>>) ->
    #certificate_request{certificate_types = CertTypes,
			 certificate_authorities = CertAuths};
dec_hs(?SERVER_HELLO_DONE, <<>>) ->
    #server_hello_done{};

dec_hs(_, _) ->
    throw({handshake_failed, invalid_handshake_data}).

decode_server_key(ServerKey, Type) ->
    dec_server_key(ServerKey, key_exchange_alg(Type), {3, 3}).



%% internal functions.

dec_hello_extensions(<<>>) ->
    [];
dec_hello_extensions(<<?UINT16(ExtLen), Extensions:ExtLen/binary>>) ->
    dec_hello_extensions(Extensions, []);
dec_hello_extensions(_) ->
    [].

dec_hello_extensions(<<>>, Acc) ->
    Acc;
dec_hello_extensions(<<?UINT16(?NEXTPROTONEG_EXT), ?UINT16(Len), ExtensionData:Len/binary, Rest/binary>>, Acc) ->
    Prop = {next_protocol_negotiation, #next_protocol_negotiation{extension_data = ExtensionData}},
    dec_hello_extensions(Rest, [Prop | Acc]);
dec_hello_extensions(<<?UINT16(?RENEGOTIATION_EXT), ?UINT16(Len), Info:Len/binary, Rest/binary>>, Acc) ->
    RenegotiateInfo = case Len of
			  1 ->  % Initial handshake
			      Info; % should be <<0>> will be matched in handle_renegotiation_info
			  _ ->
			      VerifyLen = Len - 1,
			      <<?BYTE(VerifyLen), VerifyInfo/binary>> = Info,
			      VerifyInfo
		      end,	    
    dec_hello_extensions(Rest, [{renegotiation_info, 
			   #renegotiation_info{renegotiated_connection = RenegotiateInfo}} | Acc]);

dec_hello_extensions(<<?UINT16(?SRP_EXT), ?UINT16(Len), ?BYTE(SRPLen), SRP:SRPLen/binary, Rest/binary>>, Acc)
  when Len == SRPLen + 2 ->
    dec_hello_extensions(Rest, [{srp,
			   #srp{username = SRP}} | Acc]);

dec_hello_extensions(<<?UINT16(?SIGNATURE_ALGORITHMS_EXT), ?UINT16(Len),
		       ExtData:Len/binary, Rest/binary>>, Acc) ->
    SignAlgoListLen = Len - 2,
    <<?UINT16(SignAlgoListLen), SignAlgoList/binary>> = ExtData,
    HashSignAlgos = [{ssl_cipher:hash_algorithm(Hash), ssl_cipher:sign_algorithm(Sign)} ||
			<<?BYTE(Hash), ?BYTE(Sign)>> <= SignAlgoList],
    dec_hello_extensions(Rest, [{hash_signs,
				 #hash_sign_algos{hash_sign_algos = HashSignAlgos}} | Acc]);

dec_hello_extensions(<<?UINT16(?ELLIPTIC_CURVES_EXT), ?UINT16(Len),
		       ExtData:Len/binary, Rest/binary>>, Acc) ->
    EllipticCurveListLen = Len - 2,
    <<?UINT16(EllipticCurveListLen), EllipticCurveList/binary>> = ExtData,
    EllipticCurves = [tls_v1:enum_to_oid(X) || <<X:16>> <= EllipticCurveList],
    dec_hello_extensions(Rest, [{elliptic_curves,
				 #elliptic_curves{elliptic_curve_list = EllipticCurves}} | Acc]);

dec_hello_extensions(<<?UINT16(?EC_POINT_FORMATS_EXT), ?UINT16(Len),
		       ExtData:Len/binary, Rest/binary>>, Acc) ->
    ECPointFormatListLen = Len - 1,
    <<?BYTE(ECPointFormatListLen), ECPointFormatList/binary>> = ExtData,
    ECPointFormats = binary_to_list(ECPointFormatList),
    dec_hello_extensions(Rest, [{ec_point_formats,
				 #ec_point_formats{ec_point_format_list = ECPointFormats}} | Acc]);


dec_hello_extensions(<<?UINT16(?USE_SRTP_EXT), ?UINT16(Len), 
                       ExtData:Len/binary, Rest/binary>>, Acc) ->
    <<?UINT16(2), ?UINT16(ChosenProtectionProfile), ?BYTE(MKILen), MKI:MKILen/binary>> = ExtData,
    dec_hello_extensions(Rest, [{use_srtp,
                                 #use_srtp{protection_profile = ChosenProtectionProfile,
                                           mki=MKI}} | Acc]);

%% Ignore data following the ClientHello (i.e.,
%% extensions) if not understood.

dec_hello_extensions(<<?UINT16(_), ?UINT16(Len), _Unknown:Len/binary, Rest/binary>>, Acc) ->
    dec_hello_extensions(Rest, Acc);
%% This theoretically should not happen if the protocol is followed, but if it does it is ignored.
dec_hello_extensions(_, Acc) ->
    Acc.


certs_to_list(ASN1Certs) ->
    certs_to_list(ASN1Certs, []).

certs_to_list(<<?UINT24(CertLen), Cert:CertLen/binary, Rest/binary>>, Acc) ->
    certs_to_list(Rest, [Cert | Acc]);
certs_to_list(<<>>, Acc) ->
    lists:reverse(Acc, []).

%%%
dec_ske_params(Len, Keys, Version) ->
    <<Params:Len/bytes, Signature/binary>> = Keys,
    dec_ske_signature(Params, Signature, Version).

dec_ske_signature(Params, <<?BYTE(HashAlgo), ?BYTE(SignAlgo),
			    ?UINT16(0)>>, {Major, Minor})
  when Major == 3, Minor >= 3 ->
    HashSign = {ssl_cipher:hash_algorithm(HashAlgo), ssl_cipher:sign_algorithm(SignAlgo)},
    {Params, HashSign, <<>>};
dec_ske_signature(Params, <<?BYTE(HashAlgo), ?BYTE(SignAlgo),
			    ?UINT16(Len), Signature:Len/binary>>, {Major, Minor})
  when Major == 3, Minor >= 3 ->
    HashSign = {ssl_cipher:hash_algorithm(HashAlgo), ssl_cipher:sign_algorithm(SignAlgo)},
    {Params, HashSign, Signature};
dec_ske_signature(Params, <<>>, _) ->
    {Params, {null, anon}, <<>>};
dec_ske_signature(Params, <<?UINT16(0)>>, _) ->
    {Params, {null, anon}, <<>>};
dec_ske_signature(Params, <<?UINT16(Len), Signature:Len/binary>>, _) ->
    {Params, undefined, Signature}.

dec_server_key(<<?UINT16(PLen), P:PLen/binary,
		 ?UINT16(GLen), G:GLen/binary,
		 ?UINT16(YLen), Y:YLen/binary, _/binary>> = KeyStruct,
	       ?KEY_EXCHANGE_DIFFIE_HELLMAN, Version) ->
    Params = #server_dh_params{dh_p = P, dh_g = G, dh_y = Y},
    {BinMsg, HashSign, Signature} = dec_ske_params(PLen + GLen + YLen + 6, KeyStruct, Version),
    #server_key_params{params = Params,
		       params_bin = BinMsg,
		       hashsign = HashSign,
		       signature = Signature};
%% ECParameters with named_curve
%% TODO: explicit curve
dec_server_key(<<?BYTE(?NAMED_CURVE), ?UINT16(CurveID),
		 ?BYTE(PointLen), ECPoint:PointLen/binary,
		 _/binary>> = KeyStruct,
	       ?KEY_EXCHANGE_EC_DIFFIE_HELLMAN, Version) ->
    Params = #server_ecdh_params{curve = {namedCurve, tls_v1:enum_to_oid(CurveID)},
				 public = ECPoint},
    {BinMsg, HashSign, Signature} = dec_ske_params(PointLen + 4, KeyStruct, Version),
    #server_key_params{params = Params,
		       params_bin = BinMsg,
		       hashsign = HashSign,
		       signature = Signature};
dec_server_key(<<?UINT16(Len), PskIdentityHint:Len/binary>> = KeyStruct,
	       KeyExchange, Version)
  when KeyExchange == ?KEY_EXCHANGE_PSK; KeyExchange == ?KEY_EXCHANGE_RSA_PSK ->
    Params = #server_psk_params{
      hint = PskIdentityHint},
    {BinMsg, HashSign, Signature} = dec_ske_params(Len + 2, KeyStruct, Version),
    #server_key_params{params = Params,
		       params_bin = BinMsg,
		       hashsign = HashSign,
		       signature = Signature};
dec_server_key(<<?UINT16(Len), IdentityHint:Len/binary,
		 ?UINT16(PLen), P:PLen/binary,
		 ?UINT16(GLen), G:GLen/binary,
		 ?UINT16(YLen), Y:YLen/binary, _/binary>> = KeyStruct,
	       ?KEY_EXCHANGE_DHE_PSK, Version) ->
    DHParams = #server_dh_params{dh_p = P, dh_g = G, dh_y = Y},
    Params = #server_dhe_psk_params{
      hint = IdentityHint,
      dh_params = DHParams},
    {BinMsg, HashSign, Signature} = dec_ske_params(Len + PLen + GLen + YLen + 8, KeyStruct, Version),
    #server_key_params{params = Params,
		       params_bin = BinMsg,
		       hashsign = HashSign,
		       signature = Signature};
dec_server_key(<<?UINT16(NLen), N:NLen/binary,
		 ?UINT16(GLen), G:GLen/binary,
		 ?BYTE(SLen), S:SLen/binary,
		 ?UINT16(BLen), B:BLen/binary, _/binary>> = KeyStruct,
	       ?KEY_EXCHANGE_SRP, Version) ->
    Params = #server_srp_params{srp_n = N, srp_g = G, srp_s = S, srp_b = B},
    {BinMsg, HashSign, Signature} = dec_ske_params(NLen + GLen + SLen + BLen + 7, KeyStruct, Version),
    #server_key_params{params = Params,
		       params_bin = BinMsg,
		       hashsign = HashSign,
		       signature = Signature};
dec_server_key(_, _, _) ->
    throw({handshake_failed, dec_server_key_failed}).

key_exchange_alg(rsa) ->
    ?KEY_EXCHANGE_RSA;
key_exchange_alg(Alg) when Alg == dhe_rsa; Alg == dhe_dss;
			    Alg == dh_dss; Alg == dh_rsa; Alg == dh_anon ->
    ?KEY_EXCHANGE_DIFFIE_HELLMAN;
key_exchange_alg(Alg) when Alg == ecdhe_rsa; Alg == ecdh_rsa;
			   Alg == ecdhe_ecdsa; Alg == ecdh_ecdsa;
			   Alg == ecdh_anon ->
    ?KEY_EXCHANGE_EC_DIFFIE_HELLMAN;
key_exchange_alg(psk) ->
    ?KEY_EXCHANGE_PSK;
key_exchange_alg(dhe_psk) ->
    ?KEY_EXCHANGE_DHE_PSK;
key_exchange_alg(rsa_psk) ->
    ?KEY_EXCHANGE_RSA_PSK;
key_exchange_alg(Alg)
  when Alg == srp_rsa; Alg == srp_dss; Alg == srp_anon ->
    ?KEY_EXCHANGE_SRP;
key_exchange_alg(_) ->
    ?NULL.
