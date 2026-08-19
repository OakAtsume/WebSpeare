require_relative("../../src/firewall")
require "json"

# Interactive decoy — App Config & Secret File harvesting.
#
# Contract (same as the other decoys):
# {
#   :triggered => true/false,
#   :overwrite => true/false,
#   :reason    => String,
#   :payload   => nil/String,
#   :code      => Int   # only when overwrite is true
# }
#
# Target: the month's dominant web campaign (e.g. 185.177.72.0/24, curl-based)
# that force-browses for framework config and secret files —
#   /appsettings.json  /application.yml  /application.properties  /web.config
#   /settings.py  /.env  /database.yml  /secrets.yaml  /credentials.json ...
# hunting DB creds, cloud keys, and SSH material.
#
# A real misconfigured server would return the file. This decoy plays along and
# serves a believable file whose secrets are ALL CANARIES. The point is
# attribution + waste: the scanner "wins", banks the creds, and their follow-up
# (using those creds) either lands back in our logs or trips an external canary.
#
# ── CANARIES ────────────────────────────────────────────────────────────────
# The values below are fake. For phone-home alerting on use, replace them with
# live tokens from canarytokens.org (AWS key token, MySQL token, custom URL
# token) or your own listener host. The AWS id keeps the AKIA + 20-char shape so
# it passes format validation in the attacker's tooling. Keep them recognizable
# to YOU (grep your logs / SIEM for these strings) but plausible to them.
class ConfigSecretsDecoy
  AWS_KEY_ID     = "AKIA5SPEARE7QH0NEYPT"          # replace w/ canarytokens.org AWS key
  AWS_SECRET     = "wJal9SpEaReXhk/K7MDENG+bPxRfiCYHONEYcanaR"
  DB_USER        = "svc_app"
  DB_PASS        = "Pr0d_Db!7f3a9c2e"
  DB_HOST        = "10.20.0.14"
  JWT_SECRET     = "eyJprod-signing-9f2c1b7a4e6d8c05-do-not-share"
  API_TOKEN      = "sk_live_5speare_1c9f4a7be2d6089c3f5a1b"
  CANARY_HOST    = "vault-internal.corp-metrics.net"  # point at your canary listener

  # basename (lowercased) => generator method
  MATCHES = {
    "appsettings.json"        => :dotnet_appsettings,
    "web.config"              => :dotnet_webconfig,
    "application.yml"         => :spring_yaml,
    "application.yaml"        => :spring_yaml,
    "application.properties"  => :spring_properties,
    "settings.py"            => :django_settings,
    "local_settings.py"      => :django_settings,
    ".env"                   => :dotenv,
    ".env.local"             => :dotenv,
    ".env.production"        => :dotenv,
    "database.yml"           => :rails_database,
    "secrets.yml"            => :rails_secrets,
    "secrets.yaml"           => :rails_secrets,
    "credentials.json"       => :gcp_credentials,
  }.freeze

  def runCheck(request, serverInstance)
    return passthrough unless ["GET", "HEAD"].include?(request[:method])
    path = request[:path].to_s
    return passthrough if path.empty?

    base = path.split("?").first.to_s.split("/").last.to_s.downcase
    # appsettings.Production.json / appsettings.Development.json etc.
    gen = MATCHES[base]
    gen ||= :dotnet_appsettings if base =~ /\Aappsettings\..+\.json\z/
    return passthrough unless gen

    body, ext = send(gen)
    payload = serverInstance.genReply(200, body, serverInstance.mimeFor(ext))

    {
      triggered: true,
      overwrite: true,
      reason: "Decoy-Config/Secret Harvest (served canaried #{base})",
      payload: payload,
      code: 200,
    }
  end

  private

  def passthrough
    { triggered: false, overwrite: false, reason: "blank", payload: nil }
  end

  def dotnet_appsettings
    body = JSON.pretty_generate({
      "Logging" => { "LogLevel" => { "Default" => "Information", "Microsoft.AspNetCore" => "Warning" } },
      "AllowedHosts" => "*",
      "ConnectionStrings" => {
        "DefaultConnection" => "Server=#{DB_HOST};Database=app_prod;User Id=#{DB_USER};Password=#{DB_PASS};TrustServerCertificate=True",
      },
      "Jwt" => { "Issuer" => "https://#{CANARY_HOST}", "Key" => JWT_SECRET, "ExpireMinutes" => 60 },
      "AWS" => { "Region" => "us-east-1", "AccessKey" => AWS_KEY_ID, "SecretKey" => AWS_SECRET },
      "Stripe" => { "SecretKey" => API_TOKEN },
    })
    [body, ".json"]
  end

  def dotnet_webconfig
    body = <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <configuration>
        <connectionStrings>
          <add name="DefaultConnection" connectionString="Server=#{DB_HOST};Database=app_prod;User Id=#{DB_USER};Password=#{DB_PASS};" providerName="System.Data.SqlClient" />
        </connectionStrings>
        <appSettings>
          <add key="AWSAccessKey" value="#{AWS_KEY_ID}" />
          <add key="AWSSecretKey" value="#{AWS_SECRET}" />
          <add key="JwtSigningKey" value="#{JWT_SECRET}" />
        </appSettings>
      </configuration>
    XML
    [body, ".xml"]
  end

  def spring_yaml
    body = <<~YML
      spring:
        datasource:
          url: jdbc:mysql://#{DB_HOST}:3306/app_prod
          username: #{DB_USER}
          password: #{DB_PASS}
        jpa:
          hibernate:
            ddl-auto: validate
      cloud:
        aws:
          credentials:
            access-key: #{AWS_KEY_ID}
            secret-key: #{AWS_SECRET}
          region:
            static: us-east-1
      jwt:
        secret: #{JWT_SECRET}
    YML
    [body, ".yml"]
  end

  def spring_properties
    body = <<~PROPS
      spring.datasource.url=jdbc:mysql://#{DB_HOST}:3306/app_prod
      spring.datasource.username=#{DB_USER}
      spring.datasource.password=#{DB_PASS}
      cloud.aws.credentials.access-key=#{AWS_KEY_ID}
      cloud.aws.credentials.secret-key=#{AWS_SECRET}
      cloud.aws.region.static=us-east-1
      jwt.secret=#{JWT_SECRET}
    PROPS
    [body, ".txt"]
  end

  def django_settings
    body = <<~PY
      # Django settings (production)
      import os

      SECRET_KEY = "#{JWT_SECRET}"
      DEBUG = False
      ALLOWED_HOSTS = ["#{CANARY_HOST}"]

      DATABASES = {
          "default": {
              "ENGINE": "django.db.backends.postgresql",
              "NAME": "app_prod",
              "USER": "#{DB_USER}",
              "PASSWORD": "#{DB_PASS}",
              "HOST": "#{DB_HOST}",
              "PORT": "5432",
          }
      }

      AWS_ACCESS_KEY_ID = "#{AWS_KEY_ID}"
      AWS_SECRET_ACCESS_KEY = "#{AWS_SECRET}"
      AWS_STORAGE_BUCKET_NAME = "app-prod-assets"
    PY
    [body, ".txt"]
  end

  def dotenv
    body = <<~ENV
      APP_ENV=production
      APP_DEBUG=false
      APP_URL=https://#{CANARY_HOST}
      DB_CONNECTION=mysql
      DB_HOST=#{DB_HOST}
      DB_PORT=3306
      DB_DATABASE=app_prod
      DB_USERNAME=#{DB_USER}
      DB_PASSWORD=#{DB_PASS}
      AWS_ACCESS_KEY_ID=#{AWS_KEY_ID}
      AWS_SECRET_ACCESS_KEY=#{AWS_SECRET}
      AWS_DEFAULT_REGION=us-east-1
      JWT_SECRET=#{JWT_SECRET}
      STRIPE_SECRET=#{API_TOKEN}
    ENV
    [body, ".txt"]
  end

  def rails_database
    body = <<~YML
      production:
        adapter: postgresql
        encoding: unicode
        database: app_prod
        username: #{DB_USER}
        password: #{DB_PASS}
        host: #{DB_HOST}
        port: 5432
    YML
    [body, ".yml"]
  end

  def rails_secrets
    body = <<~YML
      production:
        secret_key_base: #{JWT_SECRET}
        aws_access_key_id: #{AWS_KEY_ID}
        aws_secret_access_key: #{AWS_SECRET}
    YML
    [body, ".yml"]
  end

  def gcp_credentials
    body = JSON.pretty_generate({
      "type" => "service_account",
      "project_id" => "app-prod-241807",
      "private_key_id" => "1c9f4a7be2d6089c3f5a1b0e8d4a2c6f9b3e7d15",
      "private_key" => "-----BEGIN PRIVATE KEY-----\\nMIIBVAIBADANBg...CANARY...redacted\\n-----END PRIVATE KEY-----\\n",
      "client_email" => "app-prod@app-prod-241807.iam.gserviceaccount.com",
      "token_uri" => "https://oauth2.googleapis.com/token",
    })
    [body, ".json"]
  end
end
