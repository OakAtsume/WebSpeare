
require_relative("../../src/firewall")

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

# This is a Decoy rule.
# It's meant to make certain attacks more attractive;
# In this case we are targeting Red-Tail. A family of Malware that target's Linux systems IoT.
# This Rule will find any refrences to PATH `/hello.world` or if the body contains "Hello CVE-2024-4577"
# Then it shall return the md5sum of the string "Hello..." yk.
# Just to trigger a "Positive" 

# def ruleLog(level: :info, message: "", rule: "")
class CVE20244577_RedTailSpoofer
  def initialize()

    @shasum_with_newline = "fa3fbf99755b095f8ffde39e3440e67a"
    @shasum_without_newline = "d5c6a2deb8ac3d4e74d79d582b9f3898"
  end

  # Requests instance and Instance to the @server class.
  # Useful functions such as genRequest are present <.>
  def runCheck(request, serverInstance)


    if request[:path] == "/hello.world"
        #  genReply(code, body, mime, headers = {})


        reply = serverInstance.genReply(
            200,
            @shasum_with_newline,
            serverInstance.mimeFor(".txt")
        )
        # reply = serverInstance.genReply(
        #     666,
        #     "<h1>Your number is #{rand}</h1>",
        #     serverInstance.mimeFor(".html")
        # )
        
        return {
            triggered:true,
            overwrite:true,
            reason:"Path(/hello.world) Assuming RedTail CVE-2024-4577",
            payload: reply,
            code: 200
        }
    elsif request[:body].include?("Hello CVE-2024-4577")
        reply = serverInstance.genReply(
            200,
            "#{@shasum_with_newline}\n#{@shasum_without_newline}",
            serverInstance.mimeFor(".txt")
        )

        return {
            triggered:true,
            overwrite:true,
            reason:"Match-Body(Hello CVE-2024-4577) Assuming RedTail CVE-2024-4577",
            payload: reply,
            code: 200
        }
    end

    return {
             triggered: false,
             overwrite: false,
             reason: "blank",
             payload: nil,
           }

  end
end
