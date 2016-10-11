-ifndef(dtls4srtp).
-define(dtls4srtp, true).


-define(SRTP_AES128_CM_HMAC_SHA1_80, 16#0001).
-define(SRTP_AES128_CM_HMAC_SHA1_32, 16#0002).
-define(SRTP_NULL_HMAC_SHA1_80, 16#0005).
-define(SRTP_NULL_HMAC_SHA1_32, 16#0006).

-define(DEFAULT_KEY_LIFETIME, 4294967296).  % 2^32.

-record(protection_profile_detail, {cipher,    %% "AES_128_CM" | null
	                                cipher_key_length,
	                                cipher_salt_length,
	                                maximum_lifetime = ?DEFAULT_KEY_LIFETIME,
	                                auth_function = "HMAC-SHA1",
	                                auth_key_length,
	                                auth_tag_length,
	                                srtcp_auth_tag_length}).

-define(SRTP_AES128_CM_HMAC_SHA1_80_DETAIL,
	#protection_profile_detail{cipher = "AES_128_CM",  
                                cipher_key_length = 128,
                                cipher_salt_length = 112,
                                maximum_lifetime = ?DEFAULT_KEY_LIFETIME,
                                auth_function = "HMAC-SHA1",
                                auth_key_length = 160,
                                auth_tag_length = 80,
                                srtcp_auth_tag_length = 80}).

-define(SRTP_AES128_CM_HMAC_SHA1_32_DETAIL,
	#protection_profile_detail{cipher = "AES_128_CM",  
                                cipher_key_length = 128,
                                cipher_salt_length = 112,
                                maximum_lifetime = ?DEFAULT_KEY_LIFETIME,
                                auth_function = "HMAC-SHA1",
                                auth_key_length = 160,
                                auth_tag_length = 32,
                                srtcp_auth_tag_length = 80}).

-define(SRTP_NULL_HMAC_SHA1_80_DETAIL,
	#protection_profile_detail{cipher = null,  
                                cipher_key_length = 0,
                                cipher_salt_length = 0,
                                maximum_lifetime = ?DEFAULT_KEY_LIFETIME,
                                auth_function = "HMAC-SHA1",
                                auth_key_length = 160,
                                auth_tag_length = 80,
                                srtcp_auth_tag_length = 80}).

-define(SRTP_NULL_HMAC_SHA1_32_DETAIL,
	#protection_profile_detail{cipher = null,  
                                cipher_key_length = 0,
                                cipher_salt_length = 0,
                                maximum_lifetime = ?DEFAULT_KEY_LIFETIME,
                                auth_function = "HMAC-SHA1",
                                auth_key_length = 160,
                                auth_tag_length = 32,
                                srtcp_auth_tag_length = 80}).

-define(PROTECTION_PROFILE_DETAILS, [
    {?SRTP_AES128_CM_HMAC_SHA1_80, ?SRTP_AES128_CM_HMAC_SHA1_80_DETAIL},
    {?SRTP_AES128_CM_HMAC_SHA1_32, ?SRTP_AES128_CM_HMAC_SHA1_32_DETAIL},
    {?SRTP_NULL_HMAC_SHA1_80, ?SRTP_NULL_HMAC_SHA1_80_DETAIL},
    {?SRTP_NULL_HMAC_SHA1_32, ?SRTP_NULL_HMAC_SHA1_32_DETAIL}]).

-define(PROTECTION_PROFILE_NAMES, [
    {?SRTP_AES128_CM_HMAC_SHA1_80, "AES_CM_128_HMAC_SHA1_80"},
    {?SRTP_AES128_CM_HMAC_SHA1_32, "AES_CM_128_HMAC_SHA1_32"},
    {?SRTP_NULL_HMAC_SHA1_80, "NULL_HMAC_SHA1_80"},
    {?SRTP_NULL_HMAC_SHA1_32, "NULL_HMAC_SHA1_32"}]).

-record(srtp_params, {
                     protection_profile_name,
                     protection_profile_detail,
                     mki,
                     client_write_SRTP_master_key,
					 server_write_SRTP_master_key,
					 client_write_SRTP_master_salt,
					 server_write_SRTP_master_salt}).


-endif.
