# Title:  cert.rb
# Descr:  Returns an assortment of information about a TLS cert
# Author: Andrew O'Neill
# Date:   2017

class Cert
  require 'socket'
  require 'openssl'

  # Accept the cert common name, and then go ahead and start collecting
  # the CA's issuing information available for it
  def initialize(comname)
    tcp_client = TCPSocket.new(comname, 443)
    ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client)
    ssl_client.hostname = comname
    ssl_client.connect
    cert = OpenSSL::X509::Certificate.new(ssl_client.peer_cert)
    ssl_client.sysclose
    tcp_client.close
    
    certgoods = OpenSSL::X509::Name.new(cert.issuer).to_a
    issuer = certgoods.select { |name, data, type| name == "O" }.first[1]
    @results = { 
      valid_on: cert.not_before,
      valid_until: cert.not_after,
      issuer: issuer
   }
  end

  def get_issuer
    return @results[:issuer].to_s
  end

  def get_issue_date
    return @results[:valid_on].to_s
  end

  def get_exp_date
    return @results[:valid_until].to_s
  end
end
