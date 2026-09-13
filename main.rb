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
@page = File.read(
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

  # bait.gsub!("{{TITLE}}", baits["strings"].sample)
  # text = randomText.sample.join(" ")
  # bait.gsub!("{{POEM}}", randomWrap(text, baits["paths"], baits["params"], baits["strings"]))
  # bait.gsub!("{{FOOTER}}", "Powered by ")

  # Build one deterministic-looking bait link. Paths are benign content routes
  # (see config/baits.json) so a crawler that follows them is logged as ordinary
  # HTTP, never flagged by the WAF — that was the whole reason the old, exploit-y
  # bait paths had to be pulled.
  def baitLink
    path = @baits["paths"].sample
    if rand < 0.35 && @baits["values"] && !@baits["values"].empty?
      path = "#{path}?#{@baits["params"].sample}=#{@baits["values"].sample}"
    end
    path
  end

  def randomWrap()
    words = @randomText.sample.join(" ").split(/\b/)

    # Weave a light scatter of in-text cross-reference links through the prose.
    # Low density so it still reads like a real anthology page (camouflage), not
    # a link farm.
    body = words.map do |word|
      if word.match?(/\w/) && rand < 0.04
        "<a href=\"#{baitLink}\">#{word}</a>"
      else
        word
      end
    end.join("")

    # A subtle, realistic dev-artifact comment. This is response-only — the WAF
    # only inspects requests, so it never trips a rule; it just makes the host
    # read as a lived-in real site. Never anything that identifies a honeypot.
    body += "\n<!-- #{@baits["strings"].sample} -->" if rand < 0.6

    # Hidden crawler-trap fan-out. Screen-reader-clipped (a standard a11y pattern
    # used by countless real sites → not a honeypot fingerprint), so humans never
    # see or click these, but aggressive crawlers/scrapers follow them into an
    # effectively endless maze of benign pages.
    trap = Array.new(rand(5..9)) do
      link = baitLink
      "<a href=\"#{link}\">#{link.split("/").last.to_s.split("?").first.gsub("-", " ")}</a>"
    end.join(" ")
    body += "\n<div class=\"sr-only\" aria-hidden=\"true\">#{trap}</div>"

    body
  end
end

firewall = Firewall.new(@server)
utils = ServerUtils.new(randomText, baits, @page, record)

# Import / Register my Firewall rules here.

require_relative("waf/legacy")
# require_relative("waf/test")
require_relative("waf/decoys/redtail-hello-world")
require_relative("waf/decoys/PHPInfoDecoy")
require_relative("waf/decoys/CVE-2025-55182")
require_relative("waf/decoys/cPanel")
require_relative("waf/decoys/phpunit-rce")
require_relative("waf/decoys/upload-traversal")
require_relative("waf/decoys/config-secrets")
require_relative("waf/decoys/toolshell")
legacy = LegacyChecks.new("waf/legacyrules")
redTailSpoofer = CVE20244577_RedTailSpoofer.new()
phpinfoDecoy = PHPInfoDecoy.new()
react2Shell = CVE_2025_55182.new()
cPanel = CPanelSpoofer.new()
phpunitRce = PHPUnitRCEDecoy.new()
uploadTraversal = UploadTraversalDecoy.new()
configSecrets = ConfigSecretsDecoy.new()
toolShell = ToolShellDecoy.new()

# Method for Rule Data : Priority
firewall.register(legacy.method(:legacyChecks), 900)
firewall.register(redTailSpoofer.method(:runCheck), 101)
firewall.register(phpinfoDecoy.method(:runCheck), 102)
firewall.register(react2Shell.method(:runCheck), 103)
firewall.register(cPanel.method(:runCheck), 104)
firewall.register(phpunitRce.method(:runCheck), 105)
firewall.register(uploadTraversal.method(:runCheck), 106)
firewall.register(configSecrets.method(:runCheck), 107)
firewall.register(toolShell.method(:runCheck), 108)

# === FIREWALL END === #

# Pick a fake "old software" banner ONCE at boot (stable for the process — a real
# server doesn't change its Server header per request). Advertised on responses to
# lure CVE scanners toward known-vulnerable versions; the squid entry poses as an
# open proxy to draw relay-abuse into the logs.
serverPersonas = config["serverPersonas"] || []
serverHeaders =
  if serverPersonas.empty?
    {}
  else
    sel = config["serverPersona"]
    sel.is_a?(Integer) ? (serverPersonas[sel] || serverPersonas.sample) : serverPersonas.sample
  end
record.log(message: "Server persona: #{serverHeaders["Server"] || "(none)"}")

# Default handlers
@server.on(:request) do |id, socket, request|


  fwReply = firewall.runFirewall(request)
  # puts fwReply
  if fwReply[:triggered]
    # Hand control over to the Firewall event.
    # request[:waf] = true
    # request[:wafRule] = fwReply[:reason]
    request[:waf] = true
    request[:wafRule] = fwReply[:reason]
    record.reqLogs(request)

    if fwReply[:overwrite] && fwReply[:payload] != nil
      begin
        socket.write(fwReply[:payload])
        socket.close()
      rescue => e
        puts("Failed to send reply from firewall rule. #{fwReply.inspect}")
      end
      record.log(
        level: :attacks,
        message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Firewall: #{fwReply[:reason]})",
        code: fwReply[:code],
      )
      next
    end
    # record.log(
    #   level: :attacks,
    #   message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Firewall: #{fwReply[:reason]})",
    #   code: fwReply[:code],
    # )

  end

  # Secure.txt handler
  if request[:path] == "/.well-known/security.txt" && config["security-txt"]["enabled"]
    msg = config["security-txt"]["msg"].join("\n")
    # genReply
    socket.write(
      @server.genReply(200, msg, @server.mimeFor(".html"))
    )
    record.reqLogs(request)
    socket.close()
    record.log(
      level: :http,
      message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]}",
      code: 200,
    )
    next
  end

  content = utils.randomWrap()
  # finalPage = @page.gsub("{{CONTENT}}", content)
  finalPage = @page.dup
  # Neutral, generic title/footer — no distinctive branding a fingerprinting
  # service could signature back to this honeypot.
  finalPage.gsub!("{{TITLE}}", "Selected Works")
  finalPage.gsub!("{{POEM}}", content)
  finalPage.gsub!("{{FOOTER}}", "&copy; Selected Works")
  record.reqLogs(request)

  if config["backend-spoof"]["enabled"]
    time = rand(config["backend-spoof"]["time-min"]..config["backend-spoof"]["time-max"])
    request[:timeReply] = time

    sleep(time)
  end # :bleh:

  socket.write(
    @server.genReply(
      200,
      finalPage,
      @server.mimeFor(".html"),
      serverHeaders
    )
  )
  socket.close()

  if request[:waf]
    record.log(
      level: :attacks,
      message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Firewall: #{fwReply[:reason]})",
      code: fwReply[:code],
    )
  else
    record.log(
      level: :http,
      message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]}",
      code: 200,
    )
  end

  # if request[:path] == "/"
  #   content = @server.randomWrap("0")
  #   finalPage = @page.gsub("{{CONTENT}}", content)
  #   socket.write(
  #     @server.genReply(
  #       200,
  #       finalPage,
  #       @server.mimeFor(".html")
  #     )
  #   )
  #   socket.close()
  #   record.log(
  #     level: :http,
  #     message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["user-agent"] ? request[:headers]["user-agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]} (Homepage Served)",
  #     code: 200,
  #   )
  #   next
  # end
end

@server.on(:error) do |id, socket, error|
  puts error
  puts error.backtrace.join("\n")
  if !socket.closed?()
    begin
      socket.write(
        @server.genReply(
          400,
          "<html><body><h1>400 Bad Request</h1><p>Your browser sent a request that this server could not understand.</p></body></html>",
          @server.mimeFor(".html")
        )
      )
      socket.close()
    rescue => e
      puts e
      puts e.backtrace.join("\n")
    end
  end
end

# {:method=>"GET", :path=>"/", :version=>"HTTP/1.1", :headers=>{"host"=>"[REDACTED-PUBLIC-IP]:8081", "user-agent"=>"Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0", "accept"=>"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-language"=>"en-US,en;q=0.5", "accept-encoding"=>"gzip, deflate, br, zstd", "connection"=>"keep-alive", "upgrade-insecure-requests"=>"1", "sec-fetch-dest"=>"document", "sec-fetch-mode"=>"navigate", "sec-fetch-site"=>"none", "sec-fetch-user"=>"?1", "dnt"=>"1", "sec-gpc"=>"1", "priority"=>"u=0, i"}, :raw_headers=>["Host: localhost:8081", "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language: en-US,en;q=0.5", "Accept-Encoding: gzip, deflate, br, zstd", "Connection: keep-alive", "Upgrade-Insecure-Requests: 1", "Sec-Fetch-Dest: document", "Sec-Fetch-Mode: navigate", "Sec-Fetch-Site: none", "Sec-Fetch-User: ?1", "DNT: 1", "Sec-GPC: 1", "Priority: u=0, i"], :malformed=>false, :body=>"", :params=>{}, :host=>"127.0.0.1", :timestamp=>1767686213}

record.log(message: "Server started on #{config["server"]["host"]}:#{config["server"]["port"]}")
# host: config["server"]["host"],
#   port: config["server"]["port"],

@server.attach()
