-ifndef(dtls4srtp_record).
-define(dtls4srtp_record, true).

-include_lib("ssl/src/ssl_record.hrl").

-record(dtls_record, {type,
					version,
					record_seq,      % used in plain_text
					epoch,           % used in plain_text  
					content_raw,
					message_seq,
					content_type, 
					fragment_offset,
					fragment_length,
					fragment}).

-endif.
