require_relative("../../src/firewall")
require "json"

# This is a Decoy rule (interactive).
# Any Given Rule must reply with a hash of
# {
#   :triggered => true/false,
#   :overwrite => true/false,
#   :reason    => String,
#   :payload   => nil/String,
#   :code      => Int : Only if overwrite is true.
# }
#
# Target: the high-volume "malicious upload" campaign seen on the New York
# sensor. Attackers POST a multipart form to a grab-bag of upload endpoints
# (/api/uploads, /upload, /api/v1/files, /api/profile/avatar, ...) with a
# path-traversal filename:
#
#   Content-Disposition: form-data; name="file"; filename="../../../../server.mjs"
#   <a malicious Node server.mjs that reads AWS IMDS 169.254.169.254 for creds>
#
# The goal is to overwrite the app's server entrypoint with a credential-stealer.
# A real vulnerable app would write the file and answer with a success blob; the
# scanner keys off that to know the write landed and move to stage two.
#
# This decoy plays the vulnerable app: when it sees an upload body carrying a
# traversal filename, it returns a believable "upload succeeded" JSON pointing
# at the attacker's own filename. They think they have arbitrary file write and
# their follow-up lands in our logs instead of on a real victim.
class UploadTraversalDecoy
  def initialize()
    # filename="...something with ../ or ..\ ..."
    @traversal_filename = /filename\s*=\s*"([^"]*\.\.[\/\\][^"]*)"/i
  end

  def runCheck(request, serverInstance)
    return passthrough unless ["POST", "PUT"].include?(request[:method])

    body = request[:body].to_s
    match = body.match(@traversal_filename)
    return passthrough unless match

    # Echo back the basename the attacker tried to plant, so the response looks
    # like a genuine app that stored their file.
    raw_name = match[1]
    base = raw_name.split(/[\/\\]/).last.to_s
    base = "upload.bin" if base.empty?

    body_json = JSON.generate({
      "success" => true,
      "status"  => "stored",
      "file"    => base,
      "path"    => "/uploads/#{base}",
      "size"    => request[:body].to_s.bytesize,
    })

    reply = serverInstance.genReply(
      201,
      body_json,
      serverInstance.mimeFor(".json")
    )

    {
      triggered: true,
      overwrite: true,
      reason: "Decoy-Upload Path Traversal (faked write of #{base.inspect})",
      payload: reply,
      code: 201,
    }
  end

  private

  def passthrough
    { triggered: false, overwrite: false, reason: "blank", payload: nil }
  end
end
