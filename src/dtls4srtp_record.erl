-module(dtls4srtp_record).

-compile(export_all).

-include_lib("ssl/src/ssl_internal.hrl").
-include("dtls4srtp_handshake.hrl").
-include("dtls4srtp_record.hrl").

%-define(UINT48(X),   X:48/unsigned-big-integer).
-define(MAJOR, 16#fe).
-define(MINOR, 16#fd).

encode_flight(BeginEpoch, BeginSeqNo, CS0, Records) ->
    {NewEpoch, _, NextrySeqNo, _, Bin} = 
    lists:foldl(fun({?HANDSHAKE, Frag}, {Epoch, SeqNo, _, CS1, DG}) -> 
    	               {RecBin2, CS11} = encode_handshake(Frag, CS1, Epoch, SeqNo),
    	               {Epoch, SeqNo+1, SeqNo+1, CS11, <<DG/binary, (iolist_to_binary(RecBin2))/binary>>};
    	           ({?CHANGE_CIPHER_SPEC, _}, {Epoch, SeqNo, _, CS2, DG}) ->
    	               {RecBin4, CS22}= encode_change_cipher_spec(CS2, Epoch, SeqNo),
    	               {Epoch+1, 0, SeqNo+1, CS22, <<DG/binary, (iolist_to_binary(RecBin4))/binary>>}
    	           end, 
    	{BeginEpoch, BeginSeqNo, BeginSeqNo, CS0, <<>>}, Records),
    {NewEpoch, NextrySeqNo, Bin}.

decode_flight(Data) when is_binary(Data) ->
    flightbin_to_records(Data, []).

flightbin_to_records(<<>>, Records) -> 
    %% io:format("decoded flight:~n~p~n", [Records]),
    Records;
flightbin_to_records(<<?ALERT:8, _VerMajor:8, _VerMinor:8, _Epoch:16, _SeqNo:48, ContentLen:16,
         _Bin:(ContentLen)/binary, RestBin/binary>>, Records) ->
    %io:format("received DTLS Alert~n"),
    flightbin_to_records(RestBin, Records);
flightbin_to_records(<<?HANDSHAKE:8, VerMajor:8, VerMinor:8, Epoch:16, SeqNo:48, ContentLen:16,
	     Bin:(ContentLen)/binary, RestBin/binary>>, Records) ->
    {ContentType, _PlLen, MsgSeq, FragOffset, FragLen, FragBin} = recogonize_handshake(Bin),
    % io:format("received ContentType==~p~n", [ContentType]),
    flightbin_to_records(RestBin, Records++[#dtls_record{type=?HANDSHAKE,
													  version = {VerMajor, VerMinor},
													  record_seq = SeqNo,      % used in plain_text
													  epoch = Epoch,           % used in plain_text  
													  content_raw = Bin,
                                                      message_seq = MsgSeq,
													  content_type = ContentType, 
													  fragment_offset = FragOffset,
													  fragment_length = FragLen,
													  fragment = FragBin}]);
flightbin_to_records(<<?CHANGE_CIPHER_SPEC:8, VerMajor:8, VerMinor:8, Epoch:16, SeqNo:48, 1:16,
	     Bin:8, RestBin/binary>>, Records) ->
    flightbin_to_records(RestBin, Records++[#dtls_record{type=?CHANGE_CIPHER_SPEC,
													  version = {VerMajor, VerMinor},
													  record_seq = SeqNo,      % used in plain_text
													  epoch = Epoch,           % used in plain_text  
													  content_raw = Bin,
                                                      fragment = <<Bin>>}]).

recogonize_handshake(<<ContentType:8, PlLen:24, MsgSeq:16, FragOffset:24, FragLen:24,
	     FragBin:(FragLen)/binary>>)
    when ContentType == ?HELLO_VERIFY_REQUEST;
         ContentType == ?SERVER_HELLO;
         ContentType == ?CLIENT_HELLO;
         ContentType == ?CERTIFICATE;
         ContentType == ?SERVER_KEY_EXCHANGE;
         ContentType == ?CLIENT_KEY_EXCHANGE;
         ContentType == ?CERTIFICATE_REQUEST;
         ContentType == ?CERTIFICATE_VERIFY;
         ContentType == ?SERVER_HELLO_DONE ->
    {ContentType, PlLen, MsgSeq, FragOffset, FragLen, FragBin};
recogonize_handshake(Bin) ->
    % io:format("recieved encrypted frame..~n"),
    {?FINISHED, 0, 0, 0, 0, Bin}.


decipher_dtls_record(Fragment, ConnnectionStates0) ->
    CS0 = ConnnectionStates0#connection_states.current_read,
    SP = CS0#connection_state.security_parameters,
    BCA = SP#security_parameters.bulk_cipher_algorithm, 
    HashSz = SP#security_parameters.hash_size,
    CipherS0 = CS0#connection_state.cipher_state,
    % io:format("BCA:~p~nHashSz:~p~nCipherS0:~p~nFragment:~p~n", [BCA, HashSz, CipherS0, Fragment]),
    {T, _Mac, CipherS1} = ssl_cipher:decipher(BCA, HashSz, CipherS0, Fragment, {3,3}, true),
    %{T, _Mac, CipherS1} = decipher(BCA, HashSz, CipherS0, Fragment, {3,2}),
	CS1 = CS0#connection_state{cipher_state = CipherS1},
    {T, ConnnectionStates0#connection_states{current_read = CS1}}.

encode_handshake(Data, ConnectionStates, Epoch, SeqNo) ->
    encode_plain_txt(?HANDSHAKE, Data, ConnectionStates, Epoch, SeqNo).

encode_change_cipher_spec(ConnectionStates, Epoch, SeqNo) ->
    encode_plain_txt(?CHANGE_CIPHER_SPEC, <<1:8>>, ConnectionStates, Epoch, SeqNo).

encode_plain_txt(Type, Data, ConnectionStates, Epoch, SeqNo) ->
    #connection_states{current_write=#connection_state{
			 compression_state=CompS0,
			 security_parameters=
			 #security_parameters{compression_algorithm=CompAlg}
			}=CS0} = ConnectionStates,
    {Comp, CompS1} = compress(CompAlg, Data, CompS0),
    CS1 = CS0#connection_state{compression_state = CompS1},
    {CipherText, CS2} = cipher(Type, Comp, CS1, Epoch, SeqNo),
    CTBin = encode_tls_cipher_text(Type, CipherText, Epoch, SeqNo),
    {CTBin, ConnectionStates#connection_states{current_write = CS2}}.

encode_tls_cipher_text(Type, Fragment, Epoch, SeqNo) ->
    Length = erlang:iolist_size(Fragment),
    [<<?BYTE(Type), ?BYTE(?MAJOR), ?BYTE(?MINOR), ?UINT16(Epoch), ?UINT48(SeqNo), ?UINT16(Length)>>, Fragment].

compress(?NULL, Data, CS) ->
    {Data, CS}.


cipher(Type, Fragment, CS0, Epoch, SeqNo) ->
    Length = erlang:iolist_size(Fragment),
    {MacHash, CS1=#connection_state{cipher_state = CipherS0,
				 security_parameters=
				 #security_parameters{bulk_cipher_algorithm = 
						      BCA}
				}} = 
	hash_and_bump_seqno(CS0, Type, Length, Fragment, Epoch, SeqNo),
    {Ciphered, CipherS1} = ssl_cipher:cipher(BCA, CipherS0, MacHash, Fragment, {3, 3}),
    CS2 = CS1#connection_state{cipher_state=CipherS1},
    %io:format("[Cipher] Type:~p~nFragment:~p~nCipherS0:~p~nBCA:~p~nMacHash:~p~nCiphered:~p,CipherS1:~p~n", [Type, Fragment, CipherS0, BCA, MacHash,Ciphered,CipherS1]),
    {Ciphered, CS2}.

hash_and_bump_seqno(#connection_state{sequence_number = SeqNo,
				      mac_secret = MacSecret,
				      security_parameters = 
				      SecPars} = CS0,
		    Type, Length, Fragment, Epoch, SeqNo1) ->
    SeqNo2 = (Epoch bsl 48) bor SeqNo1,
    Hash = mac_hash(SecPars#security_parameters.mac_algorithm,
		    MacSecret, SeqNo2, Type,
		    Length, Fragment),
    {Hash, CS0#connection_state{sequence_number = SeqNo+1}}.


mac_hash(MacAlg, MacSecret, SeqNo, Type, Length, Fragment) ->
    tls_v1:mac_hash(MacAlg, MacSecret, SeqNo, Type, {?MAJOR, ?MINOR},
		      Length, Fragment).


