module PGCrypto::Extensions
  module SqlScrubber
    # SqlScrubber prevents sensitive data embedded in SQL statements from
    # being logged (which would only occur for debug loggers).
    # Example:
    #   `pgp_sym_encrypt('a-secure-field', 'my-encryption-key')`
    #    is changed to `pgp_sym_encrypt([FILTERED])`

    SCRUBBED_TEXT = '[FILTERED]'
    PGP_RE = /(?<=pgp_sym_(decrypt|encrypt)\()[^\)]*/

    def sql(event)
      return unless logger.debug?

      event.payload[:sql] = event.payload[:sql].gsub(PGP_RE, SCRUBBED_TEXT)
      super
    end
  end
end

if defined? ActiveRecord::LogSubscriber
  ActiveRecord::LogSubscriber.prepend PGCrypto::Extensions::SqlScrubber
else
  ActiveSupport.on_load(:active_record) do
    ActiveRecord::LogSubscriber.prepend PGCrypto::Extensions::SqlScrubber
  end
end
