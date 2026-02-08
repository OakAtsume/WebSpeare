require("json")


class Firewall
  def initialize(serverInstance)
    @rules = []
    @serverInstance = serverInstance
  end

  def register(rule, priority)
    @rules.push(
      {
        priority: priority,
        func: rule
      }
    )
    @rules.sort_by! { |r| r[:priority] }
  end


  def runFirewall(request)
    initial = request.dup

    @rules.each do |entry|
      rule = entry[:func]
      # Any Given Rule must reply with a hash of
      # {
      #   :triggered => true/false,
      #   :overwrite => true/false,
      #   :reason => true/false,
      #   :payload => nil/String,
      #   :code => Int : Only if overwrite is true.
      # }
      
      ruleReply = rule.call(request, @serverInstance)

      # puts("Rule Reply: #{ruleReply}")
      if ruleReply[:triggered]
        return ruleReply
      end
    end

    return {
      triggered: false,
      overwrite: false,
      reason: nil,
      payload: nil,
    }
  end
end

def ruleLog(level: :info, message: "", rule: "")
  timestamp = Time.now.strftime("%H:%M:%S")
  lvl = level.to_sym

  color = case lvl
  when :warn    then "\e[33m" # yellow
  when :error   then "\e[31m" # red
  when :trigger then "\e[35m" # magenta
  when :info    then "\e[32m" # green
  else               "\e[0m"  # default
  end

  level_str = lvl.to_s.upcase
  rule_part = rule && !rule.to_s.empty? ? "#{rule}" : ""

  puts "[#{timestamp}] (\e[31mFIREWALL\e[0m) [#{color}#{level_str}\e[0m](#{rule_part}) #{message}"
end
