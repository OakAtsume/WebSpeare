require_relative("../../src/firewall")
require 'securerandom'

class PHPInfoDecoy

  def initialize
    @template = File.read("waf/decoys/phpinfo/phpinfo.html")
    # puts @template.size
    # Stable per instance
    @hostname   = random_hostname
    @kernel     = random_kernel
    @php_ver    = ["7.4.33", "8.0.30", "8.1.12", "8.2.5"].sample
    @server_ip  = random_private_ip
    @build_date = Time.now.strftime("%b %d %Y %H:%M:%S")
  end

  def runCheck(request, serverInstance)

    trigger_paths = ["/phpinfo.php", "/info.php", "/test.php"]

    unless trigger_paths.include?(request[:path])
      return {
        triggered: false,
        overwrite: false,
        reason: "blank",
        payload: nil
      }
    end

    rendered = render_template(request)

    reply = serverInstance.genReply(
      200,
      rendered,
      serverInstance.mimeFor(".html")
    )

    return {
      triggered: true,
      overwrite: true,
      reason: "Decoy-PHPInfo Accessed (Recon)",
      payload: reply,
      code: 200
    }
  end

  private

  def render_template(request)

    replacements = {
      "{{PHP_VERSION}}"    => @php_ver,
      "{{SYSTEM}}"         => "Linux #{@hostname} #{@kernel} x86_64",
      "{{SERVER_NAME}}"    => @hostname,
      "{{SERVER_ADDR}}"    => @server_ip,
      "{{REMOTE_ADDR}}"    => request[:host],
      "{{HTTP_USER_AGENT}}" => request[:headers]["User-Agent"].to_s,
      "{{REQUEST_URI}}"    => request[:path],
      "{{SERVER_PORT}}"    => rand(1024..65535).to_s,
      "{{BUILD_DATE}}"     => @build_date
    }

    output = @template.dup
    replacements.each do |token, value|
      output.gsub!(token, value)
    end

    output
  end

  def random_hostname
    hosts = %w[web01 prod-app srv-backend mars venus alpha]
    domains = %w[example.com hosting.net corp.local]
    "#{hosts.sample}.#{domains.sample}"
  end

  def random_kernel
    [
      "5.15.0-91-generic",
      "4.18.0-425.3.1.el8.x86_64",
      "6.2.0-39-generic",
      "3.10.0-1160.el7.x86_64"
    ].sample
  end

  def random_private_ip
    "192.168.#{rand(0..255)}.#{rand(1..254)}"
  end
end