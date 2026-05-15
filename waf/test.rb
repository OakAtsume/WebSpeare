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
class TestRule
  def initialize()
    reply = "OwO"
  end

  # Requests instance and Instance to the @server class.
  # Useful functions such as genRequest are present <.>
  def runTestRule(request, serverInstance)


    if request[:path] == "/SillyBilly"
        #  genReply(code, body, mime, headers = {})

        
        reply = serverInstance.genReply(
            666,
            "<h1>Your number is #{rand}</h1>",
            serverInstance.mimeFor(".html")
        )
        return {
            triggered:true,
            overwrite:true,
            reason:"Fuck Silly Billy",
            payload: reply,
            code: 666
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
