require_relative("../src/firewall")

# This is a Firewall Rule.
# It takes in a request instance.
# and returns this
# Any Given Rule must reply with a hash of
# {
#   :triggered => true/false,
#   :overwrite => true/false,
#   :reason => true/false,
#   :payload => nil/String
# }

# This is the "Legacy Rules~!"
# It's just how the old version worked.
# Using JSON Regex rules.
# Just cuz why not? some rules don't need whole ass code lol

# def ruleLog(level: :info, message: "", rule: "")
class LegacyChecks
  def initialize(rulesFolder = "waf/legacyrules")
    @folder = rulesFolder
    @rules = []
    if Dir.exist?(@folder)
      @rules = []

      Dir.glob(File.join(@folder, "*.json")).each do |file|
        parsed = JSON.parse(File.read(file))

        case parsed
        when Array
          @rules.concat(parsed)
        when Hash
          @rules << parsed
        else
          warn "Unknown WAF rule format in #{file}"
        end
      end
    else
      puts "Legacy rules folder not found"
      exit 1
    end
    if @rules.empty?
      puts("No Rules imported.")
    end
  end

  def legacyChecks(request, serverInstance)
    # puts request
    # puts @rules
    #     {
    #   "name": "Generic Non-printable Characters",
    #   "level": "medium",
    #   "section": [
    #     "headers",
    #     "body",
    #     "url"
    #   ],
    #   "regex": "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]",
    #   "action": "drop"
    # },

    # return {
    #          triggered: false,
    #          overwrite: false,
    #          reason: nil,
    #          payload: nil,
    #        } if @rules.empty? # Skip if no rules are loaded

    infraction = ""

    begin
      @rules.each do |rule|
        # puts(">>[RULE] #{rule}")

        if rule.class == Array
          puts "Legacy Rule is an Array,#{rule}"
        elsif rule.class != Hash
          puts "Legacy Rule is not a Hash, #{rule}"
          next
        end
        points = rule["section"]
        regex = Regexp.new(rule["regex"])
        rule["name"] = "#{rule["name"]} [Legacy-Regex]" 
        # puts(">>[RULE] #{rule}")
        points.each do |point|
          case point
          when "headers"
            request[:headers].each do |key, value|
              if regex.match?(value)
                infraction = "Header: #{key} (#{value})"
                return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil,
                     }
                     
              end
            end
          when "body"
            # next if request[:body].nil?
            if regex.match?(request[:body])
              infraction = "Body: #{request[:body]}"
              return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil,
                     }
                     
            end
          when "url"
            process = request[:path].downcase
            if regex.match?(process)
              infraction = "URL: #{process}"
              puts(">>> Matched URL Regex: #{rule["regex"]} on #{process}")
              return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil,
                     }

            end

            # If the path contains encoding, decode it
            # Sometimes attackers will encode the URL with invalid data.
            # This can break the decoder and cause an error.
            # But that's okay, if the WaF can't decode it, neither will the application.

            if !request[:path].nil?
              if request[:path].include?("%")
                process = URI.decode_www_form_component(request[:path]).downcase
                if regex.match?(process)
                  infraction = "URL: #{process} (Decoded)"
                  return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil,
                     }
                     
                end
              end
            end

            if request[:params].size > 0
              request[:params].each do |key, value|
                if regex.match?(value)
                  infraction = "URL: #{value}"
                  return {
                       triggered: true,
                       overwrite: true,
                       reason: rule["name"],
                       payload: serverInstance.genReply(200,"Hi",serverInstance.mimeFor(".html")),
                       code: 200
                     }
                     
                end
              end
            end
          else
            next
          end
        end
      end
    rescue => e
      puts(">>> #{e} (#{e.backtrace.join("\n")})")
      # exit 1
    end
    return {
             triggered: false,
             overwrite: false,
             reason: "blank",
             payload: nil,
           }
  end
end
