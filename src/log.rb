require("json")
class Log4Web
  def initialize(textlogs, jsonlogs, timeformat, fileformat, greylog_conf)
    @logs = textlogs
    @json = jsonlogs
    @timeformat = timeformat
    @fileformat = fileformat
    @greylog = greylog_conf
  end

  def reqLogs(req)
    sendToGraylog(req)
    req = JSON.generate(req)
    logs = File.open("#{@json}/#{Time.now.strftime(@fileformat)}.json", "a")
    logs.write("#{req}\n")
    logs.close
  end

  # Report data to Graylog Instance 
  def sendToGraylog(request)
    return unless @greylog["enabled"]
    puts request
    request["requestStamp"] = request[:timestamp] # To avoid it being deleted by greylog lol
    begin
      socket = TCPSocket.new(@greylog["host"], @greylog["port"])

      socket.puts(JSON.generate(request))
      socket.close
    rescue => e
      log(level: :error, message: "Failed to send to Graylog: #{e.message}")
    end
  end

  

  def log(level: :info, message: "", code: nil)
    timestamp = Time.now.strftime(@timeformat)
    # Write to File
    File.open(@logs + Time.now.strftime(@fileformat) + ".log", "a") do |f|
      f.puts("[#{timestamp}] [#{level.to_s.upcase}] #{message}")
      if code
        f.puts("  #{code}")
      end
    end

    # [<cyan>timestamp</cyan>] [<green>INFO</green>] message
    case level
    when :http
      puts("[\e[36m#{timestamp}\e[0m] [\e[34m#{level.to_s.upcase}\e[0m] #{message} : #{colorcode(code)}")
    when :waf
      puts("[\e[36m#{timestamp}\e[0m] [\e[35m#{level.to_s.upcase}\e[0m] #{message} : #{colorcode(code)}")
    when :info
      puts("[\e[36m#{timestamp}\e[0m] [\e[32m#{level.to_s.upcase}\e[0m] #{message}")
    when :warn
      puts("[\e[36m#{timestamp}\e[0m] [\e[33m#{level.to_s.upcase}\e[0m] #{message}")
    when :error
      puts("[\e[36m#{timestamp}\e[0m] [\e[31m#{level.to_s.upcase}\e[0m] #{message}")
    else
      puts("[\e[36m#{timestamp}\e[0m] [\e[34m#{level.to_s.upcase}\e[0m] #{message}")
    end
  end
  def colorcode(code)
    case code
    when 200
      return "\e[32m#{code}\e[0m"
    when 404
      return "\e[31m#{code}\e[0m"
    else
      return "\e[33m#{code}\e[0m"
    end
  end
  
end
