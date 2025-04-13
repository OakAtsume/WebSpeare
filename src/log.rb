require("json")
class Log4Web
  def initialize(logs: "logs/")
    @logs = logs
  end

  def reqLogs(req)
    req = JSON.generate(req)
    logs = File.open("#{@logs}/honey.json", "a")
    logs.write("#{req}\n")
    logs.close
  end

  def log(level: :info, message: "", code: nil)
    timestamp = Time.now.strftime("%H:%M:%S")
    # Write to File
    File.open(@logs + Time.now.strftime("%Y-%m-%d") + ".log", "a") do |f|
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
      puts("[\e[36m#{timestamp}\e[0m] [\e[35m#{level.to_s.upcase}\e[0m] #{message}")
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
