require("socket")
require("openssl")
require("thread")
require("securerandom")
require("json")
require("uri")

# {"eventid":"cowrie.client.version","version":"SSH-2.0-libssh_0.11.1","message":"Remote SSH version: SSH-2.0-libssh_0.11.1","sensor":"relaynet","timestamp":"2025-04-06T21:15:41.828407Z","src_ip":"196.251.87.35","session":"eee58e6b2f89"}



# Honeypot lol
class HoneySet
  def initialize(host: "127.0.0.1", port: 8080, buffer: 4096, waf: {}, reverseProxy: true)
    @con = {
      host: host,
      port: port,
      buffer: buffer,
      waf: waf,
      reverseProxy: reverseProxy,
    }
    @events = {}

    @server = TCPServer.new(host, port)

    # Register events
    @events[:request] = []
    @events[:waf] = [] # Triggered when a WAF rule is triggered
    @events[:error] = []
    @events[:close] = []
    @events[:event] = [] # General events

    @sockets = {}
    @id = 0
    @handler = Thread.new do
      loop do
        Thread.start(@server.accept) do |socket|
          @id += 1
          loop do
            begin
              if IO.select([socket], nil, nil, 0.01)
                data = socket.recv(@con[:buffer])
                if data.nil? || data.empty?
                  emit(:close, @id, socket) # Emit close event
                  if !socket.closed?
                    socket.close # Kill the socket if an error occurs
                  end
                  break # Break the loop
                end

                begin
                  parse = requestParse(data, socket)
                  if parse.nil?
                    emit(:error, @id, socket, "Failed to parse request") # Emit error event
                    break
                  end

                  waf = wafParse(parse)

                  if waf[0]
                    emit(:waf, @id, socket, parse, waf[1], waf[2]) # Emit waf event
                    break
                  else
                    emit(:request, @id, socket, parse) # Emit request event
                  end
                rescue => e
                  emit(:error, @id, socket, e) # Emit error event
                  if !socket.closed?
                    socket.close # Kill the socket if an error occurs
                  end
                end
              end
            rescue => e
              emit(:error, @id, socket, e) # Emit error event
              if !socket.closed?
                socket.close # Kill the socket if an error occurs
              end
              break
            end
          end
        end
      end
    end
  end

  attr_reader :con

  def wafParse(request)
    infraction = ""

    begin
      @con[:waf].each do |rule|
        points = rule["section"]
        regex = Regexp.new(rule["regex"])
        # puts(">>[RULE] #{rule}")
        points.each do |point|
          case point
          when "headers"
            request[:headers].each do |key, value|
              if regex.match?(value)
                infraction = "Header: #{key} (#{value})"
                return [true, rule, infraction]
              end
            end
          when "body"
            # next if request[:body].nil?
            if regex.match?(request[:body])
              infraction = "Body: #{request[:body]}"
              return [true, rule, infraction]
            end
          when "url"
            process = request[:path].downcase
            if regex.match?(process)
              infraction = "URL: #{process}"
              return [true, rule, infraction]
            end

            # If the path contains encoding, decode it
            # Sometimes attackers will encode the URL with invalid data.
            # This can break the decoder and cause an error.
            # But that's okay, if the WaF can't decode it, neither will the application.

            if request[:path].include?("%")
              process = URI.decode_uri_component(request[:path]).downcase
              if regex.match?(process)
                infraction = "URL: #{process} (Decoded)"
                return [true, rule, infraction]
              end
            end

            if request[:params].size > 0
              request[:params].each do |key, value|
                if regex.match?(value)
                  infraction = "URL: #{value}"
                  return [true, rule, infraction]
                end
              end
            end
          else
            next
          end
        end
      end
    rescue => e
      # puts(">>> #{e} (#{e.backtrace.join("\n")})")
      # exit 1
    end

    return [false, nil, nil]
  end

  def requestParse(data, socket)
    request = {
      :method => nil,
      :path => nil,
      :version => nil,
      :headers => {},
      :body => nil,
      :params => {},
      :host => socket.peeraddr[2], # Get the IP address of the client
      :timestamp => Time.now.to_s
    }
    begin
      raw = data.split("\r\n")
      request[:method], request[:path], request[:version] = raw[0].split(" ")
      raw.shift

      raw.each do |line|
        if line.include?(":")
          key, value = line.split(": ")
          request[:headers][key] = value
        end
      end
      if request[:headers].key?("Content-Length")
        request[:body] = raw[-1]
      end

      if @con[:reverseProxy] # Are we using a reverse proxy?
        if request[:host] == "127.0.0.1" || request[:host] == "0.0.0.0" # If the host is localhost
          if request[:headers].key?("X-Forwarded-For") || request[:headers].key?("X-Real-IP")
            request[:headers]["X-Forwarded-For"] = request[:headers]["X-Forwarded-For"] || request[:headers]["X-Real-IP"] # Get the IP address from the reverse proxy
            request[:host] = request[:headers]["X-Forwarded-For"] # Set the host to the IP address from the reverse proxy
          end
        end
      end

      if request[:path].include?("?")
        request[:path], request[:params] = request[:path].split("?")
        request[:params] = URI.decode_www_form(request[:params]).to_h
      end
      request[:timestamp] = Time.now.to_i
      return request
    rescue => e
      emit(:error, @id, socket, e) # Emit error event
      nil
    end
  end

  def on(event, &block)
    @events[event] << block
  end

  def emit(event, *args)
    @events[event].each do |block|
      block.call(*args)
    end
  end

  def reply(code, body, mime, headers = {})
    response = ""
    response += "HTTP/1.1 #{code}\r\n"
    response += "X-Content-Type-Options: nosniff\r\n"
    response += "X-Download-Options: noopen\r\n"
    response += "X-Frame-Options: SAMEORIGIN\r\n"
    response += "X-Permitted-Cross-Domain-Policies: none\r\n"
    response += "X-XSS-Protection: 1; mode=block\r\n"
    response += "Content-Type: #{mime}\r\n"
    response += "Content-Length: #{body.bytesize}\r\n"
    response += "Connection: close\r\n"
    headers.each do |key, value|
      response += "#{key}: #{value}\r\n"
    end
    response += "\r\n"
    response += body
    return response
  end

  def mimeFor(path)
    case path.split(".")[-1]
    when "html"
      return "text/html"
    when "css"
      return "text/css"
    when "js"
      return "text/javascript"
    when "png"
      return "image/png"
    when "jpg"
      return "image/jpg"
    when "jpeg"
      return "image/jpeg"
    when "gif"
      return "image/gif"
    when "svg"
      return "image/svg+xml"
    when "ico"
      return "image/x-icon"
    else
      return "text/plain"
    end
  end
  def attach()
    @handler.join # This is to keep the server running (should work with docker)
  end
  
end
