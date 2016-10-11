-module(webrtc_cert).
-include_lib("public_key/include/public_key.hrl"). 

-export([gen_key/0]).
-export([create_cert/1]).

-define(CURVE, secp256r1).


%% Create a new ECDH key pair
gen_key() ->
  {PubKey, PrivKey} = crypto:generate_key(ecdh, ?CURVE),
  #'ECPrivateKey'{
    version = 1,
    privateKey = PrivKey,
    parameters = {namedCurve, pubkey_cert_records:namedCurves(?CURVE)},
    publicKey = PubKey}.


%% Create a self-signed certificate for given key
create_cert(#'ECPrivateKey'{} = Key) ->
  Self = {rdnSequence, [
      % CN=Flussonic
      [#'AttributeTypeAndValue'{type = {2,5,4,3}, value = {utf8String,"Flussonic"}}]
    ]},

  TBSCert = #'OTPTBSCertificate'{
    version = v3, serialNumber = gen_serial(),
    signature = signature(),
    issuer = Self,
    validity = gen_validity(),
    subject = Self,
    subjectPublicKeyInfo = pubkey_info(Key),
    extensions = []
  },

  public_key:pkix_sign(TBSCert, Key).



gen_serial() ->
  Now = erlang:system_time(milli_seconds),
  Rand = crypto:strong_rand_bytes(4),
  binary:decode_unsigned(<<Now:48, Rand/binary>>).


posix_to_utctime(PosixTime) ->
  {{YYYY, MM, DD}, {H, M, S}} = erlang:posixtime_to_universaltime(PosixTime),
  lists:flatten([[io_lib:format("~2.10.0B", [P]) || P <- [YYYY rem 100, MM, DD, H, M, S]], "Z"]).

gen_validity() ->
  Now = erlang:system_time(seconds),
  Yesterday = Now - 24 * 3600,
  OneYrFwd = Yesterday + 365 * 24 * 3600,
  #'Validity'{
    notBefore = {utcTime,posix_to_utctime(Yesterday)},
    notAfter = {utcTime,posix_to_utctime(OneYrFwd)}
  }.

signature() ->
  #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256'}.

pubkey_info(#'ECPrivateKey'{publicKey = PubKey, parameters = Params}) ->
  #'OTPSubjectPublicKeyInfo'{
    algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = Params},
    subjectPublicKey = #'ECPoint'{point = PubKey}
  }.
