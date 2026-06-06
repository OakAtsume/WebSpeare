
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
class CPanelSpoofer
  def initialize()

#     /login/
# /___proxy_subdomain_whm/login/
# /whm/
# /cpanel/

    @paths = [
        "/___proxy_subdomain_whm/login/",
        "/cpanel/",
        "/whm/",
        "/login/",
        "/webmail/",
        "/roundcube",
        "/horde/",
        "/mail/"

    ]
    @page = File.read("waf/decoys/cpanel/cpanel.html")
  end

  # Requests instance and Instance to the @server class.
  # Useful functions such as genRequest are present <.>
  def runCheck(request, serverInstance)


    if @paths.include?(request[:path]) && request[:method] == "POST"
        #  genReply(code, body, mime, headers = {})


        reply = serverInstance.genReply(
            401,
            '{"status":0,"msg":"Access denied"}',
            'application/json'
        )
        return {
            triggered:true,
            overwrite:true,
            reason:"CPanel POST Attempt, serving 'Access denied'",
            payload: reply,
            code: 401
        }
    elsif @paths.include?(request[:path]) && request[:method] == "GET"
        reply = serverInstance.genReply(
            200,
            @page,
            serverInstance.mimeFor(".html")
        )

        return {
            triggered:true,
            overwrite:true,
            reason:"CPanel GET request. Serving fake login page",
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
