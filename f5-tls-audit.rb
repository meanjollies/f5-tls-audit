#!/usr/bin/env ruby

# Title:  f5-tls-audit.rb
# Descr:  Attempts to audit all TLS certs in an F5 load balancer for those issued before
#         a specific date by one or more particular certificate authorities.
# Author: Andrew O'Neill
# Date:   2017

$LOAD_PATH.unshift __dir__ + '/lib'

require 'net/https'
require 'socket'
require 'json'
require 'colorize'
require 'highline'
require 'cert'
require 'date'
require 'yaml'

# Load params needed to perform the audit
opts = YAML.load_file(__dir__ + '/conf/options.yaml')

# Make sure required params are set
opts['f5'].each do |k, v|
  raise "#{k} is not set" if v.length == 0
end

# Get the API password to the F5
opts['f5']['password'] = HighLine.new.ask("Enter the password for the F5 #{opts['f5']['user']} account:") { |q| q.echo = false }
raise "Password is required" if opts['f5']['password'].length == 0 

# Does the domain even have its cert properly configured?
def ssl_connect?(domain, port)
  begin
    Timeout::timeout(1) do
      begin
        s = TCPSocket.new(domain, port)
        s.close
        return true
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        return false
      end
    end
  rescue Timeout::Error
  end
  return false
end

# Does the domain have an associated A record?
def domain_exists?(domain)
  begin
    Socket.gethostbyname(domain)
  rescue SocketError
    return false
  end
  return true
end

# Create a connection to the F5 and get the list of all certs
http = Net::HTTP.new(opts['f5']['host'], opts['f5']['port'])
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
req = Net::HTTP::Get.new(opts['f5']['request'])
req.basic_auth(opts['f5']['user'], opts['f5']['password'])
res = http.request(req)
json = JSON.parse(res.body)

# Create empty arrays for domains that may be problematic later
unresolv_list = []
nossl_list = []

# Go through each domain and begin the audit
json['items'].each do |i|
  next if opts['certs']['exclude'].include? i['commonName'] # Ignore domains we don't care about

  # Begin audit process
  if i['commonName'] =~ /^[*a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$/ # Check domains only

    # Add domain to list to be manually checked later
    if ! domain_exists?(i['commonName'])
      unresolv_list.push(i['commonName'])
      next
    end
    if ! ssl_connect?(i['commonName'], 443)
      nossl_list.push(i['commonName'])
      next
    end

    # Get cert info based on the common name
    cert = Cert.new(i['commonName'])
    cert_issuer = cert.get_issuer
    cert_issue_date = cert.get_issue_date
    cert_exp_date = cert.get_exp_date

    # Check and use the right color based off the CA and the issue date
    if Date.parse(cert_issue_date) <= Date.parse(opts['f5']['deadline']) and opts['certs']['flagged'].include? cert_issuer
      cert_issue_date = cert_issue_date.colorize(:red)
      cert_issuer = cert_issuer.colorize(:yellow)
    end

    # Check and use the right color based off the expiration
    if Date.parse(cert_exp_date) < Date.today
      cert_exp_date = cert_exp_date.colorize(:red)
      cert_issuer = cert_issuer.colorize(:yellow)
    end

    # Dump out our audit results
    puts i['commonName']
    puts "    Issuer:     #{cert_issuer}"
    puts "    Issue Date: #{cert_issue_date}"
    puts "    Exp Date:   #{cert_exp_date}"
  end
end

# Dump out list of any domains that need to be manually checked
if ! unresolv_list.empty?
  puts "\nThe following certs do not have associated A records:"
  unresolv_list.uniq.each do |i|
    puts i
  end
end
if ! nossl_list.empty?
  puts "\nThe following certs have A records, which may be incorrect or misconfigured:"
  nossl_list.uniq.each do |i|
    puts i
  end
end
