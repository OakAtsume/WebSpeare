require("socket")
require("openssl")
require("thread")
require("securerandom")
require("json")
require("uri")

require_relative("src/back.rb")
require_relative("src/log.rb")

config = JSON.parse(File.read("config/config.json"))

server = HoneySet.new(
  waf: JSON.parse(File.read(config["waf"]["rules"])),
  host: config["server"]["host"],
  port: config["server"]["port"],
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

# def initialize(textlogs, jsonlogs, timeformat, fileformat)
record = Log4Web.new(
  config["logs"]["textpath"],
  config["logs"]["jsonpath"],
  config["logs"]["timeformat"],
  config["logs"]["fileformat"],
  config["graylog"]
)

# server = HoneySet.new(
#   waf: JSON.parse(File.read("config/waf/rules.json")),
#   port: 8081,
#   host: "0.0.0.0"
# )
# randomText = JSON.parse(File.read("config/poems.json"))
# baits = JSON.parse(File.read("config/baits.json"))
# page = File.read("config/site.html")
# record = Log4Web.new(logs: "logs/")

def randomWrap(text, inserts, params, strings)
  # puts text
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

record.log(level: :info, message: "Server started on #{server.con[:host]}:#{server.con[:port]}")

server.on(:request) do |id, socket, request|

  # Handle the attack map here!
  # if request[:path] == "/map" && request[:host] == "127.0.0.1"
  #   socket.write(
  #     server.reply(
  #       200,
  #       File.read("config/attack-map.html"),
  #       server.mimeFor(".html")
  #     )
  #   )
  #   next
  # elsif request[:path] == "/api/latest_attacks" && request[:host] == "127.0.0.1"
  #   socket.write(
  #     server.reply(
  #       200,
  #       File.read("/tmp/a.json"),
  #       server.mimeFor(".json")
  #     )
  #   )
  #   next
  # end


  if request[:path] == "/.well-known/security.txt" && config["security-txt"]["enabled"]
    msg = config["security-txt"]["msg"].join("\n")
    socket.write(
      server.reply(
        200,
        msg,
        server.mimeFor(".txt")
      )
    )
    next
  end

  # Handle robots.txt
  begin
    if request[:path].include?("/robots.txt")
      msg = "User-agent: *"
      baits["paths"].each do |path|
        msg += "\nAllow: #{path}"
      end
      socket.write(
        server.reply(
          200,
          msg,
          server.mimeFor(".txt")
        )
      )
      record.log(
        level: :http,
        message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["User-Agent"] ? request[:headers]["User-Agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]}",
        code: 200,
      )
      record.reqLogs(request)
      next
    end
  rescue => e
    # puts e
    next
  end
  code = baits["return-shifter"]["default"]

  if baits["return-shifter"]["enabled"]
    if rand < baits["return-shifter"]["chance"]
      code = baits["return-shifter"]["return-codes"].sample
    end
    # baits["return-shifter"]["return-codes"]
  end

  bait = page.dup
  bait.gsub!("{{TITLE}}", baits["strings"].sample)
  text = randomText.sample.join(" ")
  bait.gsub!("{{POEM}}", randomWrap(text, baits["paths"], baits["params"], baits["strings"]))
  bait.gsub!("{{FOOTER}}", "Powered by ")

  if baits["backend-spoof"]["enabled"]
    # server.headersReply(code,server.mimeFor(".html"))
    # First we send just the headers. Then the body (Spoofing a backend)

    socket.write(server.headersReply(code, bait.bytesize, server.mimeFor(".html")))
    time = rand(baits["backend-spoof"]["time-min"]..baits["backend-spoof"]["time-max"])
    # puts("Spoofing backend: pausing for: #{time}")
    request[:timeReply] = time
    sleep(time)
    # puts("sending body now (spoof)")

    socket.write(bait)
  else
    socket.write(
      server.reply(
        code,
        bait,
        server.mimeFor(".html")
      )
    )
  end

  # socket.write(
  #   server.reply(
  #     200,
  #     bait,
  #     server.mimeFor(".html")
  #   )
  # )

  record.log(
    level: :http,
    message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["User-Agent"] ? request[:headers]["User-Agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]}",
    code: code,
  )
  record.reqLogs(request)
end

# This will trigger a block on one's self.
# TODO: Push request method to the WaF to have the proper IP of the host.
# The request parser will parse and extract the IP from Headers or such.

server.on(:waf) do |id, socket, request, rule, data|
  if request[:path] == "/"
    request[:path] = "index.html"
  end

  if request[:path] == ".well-known/security.txt" && config["security-txt"]["enabled"]
    msg = config["security-txt"]["msg"].join("\n")
    socket.write(
      server.reply(
        200,
        msg,
        server.mimeFor(".html")
      )
    )
    next
  end

  code = baits["return-shifter"]["default"]

  if baits["return-shifter"]["enabled"]
    if rand < baits["return-shifter"]["chance"]
      code = baits["return-shifter"]["return-codes"].sample
    end
    # baits["return-shifter"]["return-codes"]
  end

  bait = page.dup
  bait.gsub!("{{TITLE}}", baits["strings"].sample)
  text = randomText.sample.join(" ")
  bait.gsub!("{{POEM}}", randomWrap(text, baits["paths"], baits["params"], baits["strings"]))
  bait.gsub!("{{FOOTER}}", "Powered by ")

  # if rule["name"].include?("SQL") && rand < 0.1 # Assume SQL Injection detection
  #   # Fake "SQL Database Is Down!
  #   puts("FAKING DOWN DATABASE")
  #   sleep 4
  #   socket.write("HTTP/1.1 504 Gateway Timeout\r\n\r\n")
  # elsif rand < 0.4 # Malformed Data
  #   puts("FAKING MALFORED DATA")
  #   socket.write("HTTP/1.1 200 Ok\r\n")
  #   socket.write("Content-Type: application/json\r\n")
  #   socket.write("Transfer-Encoding: chunked\r\n")
  #   puts("Pause 1")
  #   sleep(rand(0.5..1.5))
  #   socket.write("7\r\n")
  #   socket.write("{\"stat\"\r\n")
  #   puts("Pause 2")
  #   sleep(rand(0.5..1.5))
  #   socket.write("us\":ok\"}\r\n")
  #   socket.write("0\r\n")
  #   puts("Done")

  # else
  if baits["backend-spoof"]["enabled"]

    # server.headersReply(code,server.mimeFor(".html"))
    # First we send just the headers. Then the body (Spoofing a backend)
    socket.write(server.headersReply(code, bait.bytesize, server.mimeFor(".html")))
    time = rand(baits["backend-spoof"]["time-min"]..baits["backend-spoof"]["time-max"])
    # puts("Spoofing backend: pausing for: #{time}")
    request[:timeReply] = time
    sleep(time)
    # puts("sending body now (spoof)")
    socket.write(bait)
  else
    socket.write(
      server.reply(
        code,
        bait,
        server.mimeFor(".html")
      )
    )
  end
  # end

  request[:waf] = true
  request[:wafRule] = rule
  record.log(
    level: :waf,
    message: "#{request[:method]} #{request[:path]} #{request[:version]} #{request[:headers]["User-Agent"] ? request[:headers]["User-Agent"] : "No Agent"} B(#{request[:body] ? request[:body].size : 0}) #{request[:params] ? request[:params].to_s : "No Params"} #{request[:host]}",
    code: code,
  )
  record.reqLogs(request)
end

server.on(:error) do |id, socket, error|
  if !socket.closed?

    # puts server.con[:paths]
    begin
      socket.write(
        server.reply(
          400, # Bad Request
          "Invalid reques!",
          server.mimeFor(".html"),
        )
      )
    rescue => e
      # Host probably closed it from their side without a proper "FIN"
    end

    record.log(
      level: :http,
      message: "Invalid request from #{socket.peeraddr[3]} #{error} #{error.backtrace.join("\n")}",
      code: 400,
    )
    socket.close
  end
end

# Keep the server running

# Attach to the server
server.attach()
