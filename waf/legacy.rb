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

      # Sorted so load order (and therefore same-severity rule precedence) is
      # deterministic instead of depending on filesystem glob order.
      Dir.glob(File.join(@folder, "*.json")).sort.each do |file|
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

    # Precompile each rule's regex ONCE at load time. Previously every rule was
    # recompiled via Regexp.new on every single request inside the hot loop
    # (~N rules x every request); compiling here and stashing the Regexp on the
    # rule means the request path just reuses it. A rule with a missing or
    # invalid regex is dropped now (with a warning) so a bad pattern can never
    # reach — or crash — the per-request path.
    compiled = []
    @rules.each do |rule|
      next unless rule.is_a?(Hash)
      unless rule.key?("regex")
        # Non-rule entries (e.g. comment-only {"_note": ...} objects) are kept
        # out of the active set entirely.
        next
      end
      begin
        rule[:compiled] = Regexp.new(rule["regex"])
        compiled << rule
      rescue RegexpError => e
        warn "Skipping WAF rule #{rule["name"].inspect}: invalid regex (#{e.message})"
      end
    end

    # First-match-wins means precedence matters: a generic medium "fingerprint"
    # rule used to shadow a specific critical "exploit" rule that matched the
    # same path (e.g. /geoserver/ probe hiding a GeoServer RCE). Sort the active
    # set by severity (critical -> low) so the worst classification a request
    # qualifies for is the one reported. Stable within a severity via the index
    # tiebreak, preserving the deterministic file order for same-level rules.
    severityRank = { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3 }
    @rules = compiled
      .each_with_index
      .sort_by { |rule, idx| [severityRank.fetch(rule["level"], 4), idx] }
      .map { |rule, _idx| rule }
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

    # Decode the URL-encoded path ONCE, defensively. If an attacker sends a
    # deliberately broken %-sequence (e.g. /%zz/../../etc/passwd) the decode
    # raises ArgumentError; we must swallow it here so it can't abort the whole
    # rule loop and let the rest of the payload slip past unchecked.
    decodedPath = nil
    if !request[:path].nil? && request[:path].include?("%")
      begin
        decodedPath = URI.decode_www_form_component(request[:path]).downcase
      rescue ArgumentError
        decodedPath = nil # Undecodable for us means undecodable for the app too.
      end
    end

    @rules.each do |rule|
      # Each rule runs in its own rescue so a single bad regex/encoding can't
      # disable every rule that follows it.
      begin
        # puts(">>[RULE] #{rule}")

        if rule.class == Array
          puts "Legacy Rule is an Array,#{rule}"
          next
        elsif rule.class != Hash
          puts "Legacy Rule is not a Hash, #{rule}"
          next
        end
        regex = rule[:compiled]
        next if regex.nil?
        points = rule["section"]
        # rule["name"] = "#{rule["name"]} [Legacy-R" 
        # puts(">>[RULE] #{rule}")
        points.each do |point|
          case point
          when "method"
            # The HTTP verb itself. Lets rules classify WebDAV / upload / debug
            # methods and otherwise-unknown verbs that the parser accepted as
            # well-formed (uppercase, <=10 chars) but that are still anomalous.
            if !request[:method].nil? && regex.match?(request[:method])
              infraction = "Method: #{request[:method]}"
              return {
                     triggered: true,
                     overwrite: false,
                     reason: rule["name"],
                     payload: nil,
                   }
            end
          when "version"
            if !request[:version].nil? && regex.match?(request[:version])
              infraction = "Version: #{request[:version]}"
              return {
                     triggered: true,
                     overwrite: false,
                     reason: rule["name"],
                     payload: nil,
                   }
            end
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
              # puts(">>> Matched URL Regex: #{rule["regex"]} on #{process}")
              return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil,
                     }

            end

            # If the path contained encoding, match against the pre-decoded
            # copy too. Attackers sometimes encode payloads with invalid data;
            # that's fine — if the WAF can't decode it, neither can the app, and
            # decodedPath stays nil so we simply skip this branch.
            if !decodedPath.nil? && regex.match?(decodedPath)
              infraction = "URL: #{decodedPath} (Decoded)"
              return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil,
                     }
            end

            if request[:params].size > 0
              request[:params].each do |key, value|
                if regex.match?(value)
                  infraction = "URL: #{value}"
                  return {
                       triggered: true,
                       overwrite: false,
                       reason: rule["name"],
                       payload: nil
                     }
                     
                end
              end
            end
          else
            next
          end
        end
      rescue => e
        puts(">>> #{e} (#{e.backtrace.join("\n")})")
        next # Skip the offending rule, keep checking the rest.
      end
    end
    return {
             triggered: false,
             overwrite: false,
             reason: "blank",
             payload: nil,
           }
  end
end
