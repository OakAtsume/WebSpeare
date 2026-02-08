require("socket")
require("openssl")
require("thread")
require("securerandom")
require("json")
require("uri")

require_relative("src/back.rb")
require_relative("src/log.rb")
require_relative("src/firewall.rb")

config = JSON.parse(File.read("config/config.json"))

@server = HoneySet.new(
  host: config["server"]["host"],
  port: config["server"]["port"],
  configs: config,
)

randomText = JSON.parse(File.read(
  config["web"]["poems"]
))
baits = JSON.parse(File.read(
  config["web"]["baits"]
))
page = File.read(
  config["web"]["page"]
)

record = Log4Web.new(
  config["logs"]["textpath"],
  config["logs"]["jsonpath"],
  config["logs"]["timeformat"],
  config["logs"]["fileformat"],
  config["graylog"]
)

class ServerUtils
  def initialize(randomText, baits, page, record)
    @randomText = randomText
    @baits = baits
    @page = page
    @record = record
  end

  def randomWrap(text, insert, params, strings)
    words = text.split(/\b/)
    words.map! do |word|
      if word.match?(/\w/) && rand < 0.50
        "<a href=\"#{inserts.sample}\">#{word}</a>"
      elsif word.match?(/\w/) && rand < 0.25
        "<a href=\"#{inserts.sample}?#{params.sample}=#{inserts.sample}\">#{word}</a>"
      elsif word.match?(/\w/) && rand < 0.50
        "#{word} <!--  #{strings.sample}  -->"
      else
        word
      end
    end

    return words.join("")
  end
end



firewall = Firewall.new(@server)
utils = ServerUtils.new(randomText, baits, page, record)

# Import / Register my Firewall rules here.
require_relative("waf/legacy")
legacy = LegacyChecks.new("waf/legacyrules")
firewall.register(legacy.method(:legacyChecks), 100)

# a = Firewall.new(@server)
# a.register(method(:check))
# a.run()

# Default handlers
@server.on(:request) do |id, socket, request|
  # puts request
  # puts firewall.runFirewall(request)

  # socket.write("HTTP/1.1 200 OK\r\n")
  # socket.write("Content-Type: text/html\r\n")
  # msg = "You said : #{JSON.pretty_generate(request)}\n\n\nThe firewall said : #{JSON.pretty_generate(firewall.runFirewall(request))}"
  # socket.write("Content-Length: #{msg.bytesize}\r\n")
  # socket.write("Connection: close\r\n")
  # socket.write("\r\n")
  # socket.write(msg)
  # socket.close

  fwReply = firewall.runFirewall(request)
  # puts fwReply
  if fwReply[:triggered]
    # Hand control over to the Firewall event.
    request[:waf] = true
    request[:wafRule] = fwReply[:reason]
    if fwReply[:overwrite] && fwReply[:payload] != nil
      begin
        record.log(
          level: :http,
          message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Firewall: #{fwReply[:reason]})",
          code: fwReply[:code],
        )
        record.reqLogs(request)
        socket.write(fwReply[:payload])
        socket.close()
      rescue => e
        puts("Failed to send reply from firewall rule. #{fwReply.inspect}")
      end
      next
    end
  end

  # Secure.txt handler
  if request[:path] == "/.well-known/security.txt" && config["security-txt"]["enabled"]
    msg = config["security-txt"]["msg"].join("\n")
    socket.write(
      server.reply(
        200,
        msg,
        server.mimeFor(".txt")
      )
    )
    socket.close()
    record.log(
      level: :http,
      message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Security.txt Served)",
      code: 200,
    )
    next
  end

  if request[:path] == "/"
    content = @server.randomWrap(
      @randomText["poems"].sample,
      @baits["inserts"],
      @baits["params"],
      @baits["strings"]
    )
    finalPage = @page.gsub("{{CONTENT}}", content)
    socket.write(
      @server.genReply(
        200,
        finalPage,
        @server.mimeFor(".html")
      )
    )
    socket.close()
    record.log(
      level: :http,
      message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Homepage Served)",
      code: 200,
    )
    next
  end
end

# {:method=>"GET", :path=>"/", :version=>"HTTP/1.1", :headers=>{"host"=>"[REDACTED-PUBLIC-IP]:8081", "user-agent"=>"Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0", "accept"=>"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-language"=>"en-US,en;q=0.5", "accept-encoding"=>"gzip, deflate, br, zstd", "connection"=>"keep-alive", "upgrade-insecure-requests"=>"1", "sec-fetch-dest"=>"document", "sec-fetch-mode"=>"navigate", "sec-fetch-site"=>"none", "sec-fetch-user"=>"?1", "dnt"=>"1", "sec-gpc"=>"1", "priority"=>"u=0, i"}, :raw_headers=>["Host: localhost:8081", "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language: en-US,en;q=0.5", "Accept-Encoding: gzip, deflate, br, zstd", "Connection: keep-alive", "Upgrade-Insecure-Requests: 1", "Sec-Fetch-Dest: document", "Sec-Fetch-Mode: navigate", "Sec-Fetch-Site: none", "Sec-Fetch-User: ?1", "DNT: 1", "Sec-GPC: 1", "Priority: u=0, i"], :malformed=>false, :body=>"", :params=>{}, :host=>"127.0.0.1", :timestamp=>1767686213}

@server.attach()
