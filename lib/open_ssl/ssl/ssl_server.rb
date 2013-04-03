# make sure this is loaded before we monkey-patch
require 'openssl'

# we modify accept to only accept the socket, not do the ssl handshake. Puma does the handshake in a worker thread, so that 
# clients cant block on the handshake
module OpenSSL
  module SSL
    class SSLServer
      def accept
        sock = @svr.accept
      end
    end
  end
end
