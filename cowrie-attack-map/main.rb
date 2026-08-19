require "socket"
require "openssl"
require "thread"
require "securerandom"
require "json"
require "uri"
require "time"
require_relative("../src/back") # HoneySet
require "maxmind/geoip2"
require "fileutils"

# ============================================================================
#  Cowrie Attack Map  —  2026-06
#
#  A sibling of ../attack-map tuned for Cowrie SSH/Telnet honeypot logs.
#  Same architecture (tail → classify → Hub → SSE/ring/stats → canvas map),
#  different log schema.
#
#  Pipeline:   cowrie.json  ──tail──▶  classify  ──▶  Hub
#                                                       │
#               SSE  /api/stream  ◀── broadcast ────────┤
#               GET  /api/recent  ◀── ring buffer ──────┤
#               GET  /api/stats   ◀── live aggregates ──┘
#
#  Self-contained: ships its own vector world map, no runtime CDN calls.
# ============================================================================

# --- LogTailer -------------------------------------------------------------
# Reads appended lines from a file; survives rotation (inode change) and
# truncation. Cowrie rotates by rename, so the inode check handles it.
class LogTailer
  def initialize(log_file_path)
    @log_file_path = log_file_path
    @file_handle = nil
    @last_pos = 0
    @last_inode = nil
    initial_file_setup
  end

  def initial_file_setup
    dir = File.dirname(@log_file_path)
    FileUtils.mkdir_p(dir) unless File.directory?(dir)
    FileUtils.touch(@log_file_path) unless File.exist?(@log_file_path)

    @file_handle.close if @file_handle && !@file_handle.closed?

    begin
      @file_handle = File.open(@log_file_path, "r")
      @file_handle.seek(0, IO::SEEK_END)
      @last_pos = @file_handle.pos
      @last_inode = File.stat(@log_file_path).ino
      puts "LogTailer: tailing '#{@log_file_path}' from byte #{@last_pos}"
    rescue Errno::ENOENT
      @file_handle = nil; @last_pos = 0; @last_inode = nil
      puts "LogTailer: '#{@log_file_path}' not found yet; will retry."
    rescue => e
      puts "LogTailer: setup error for '#{@log_file_path}': #{e.message}"
      @file_handle = nil; @last_pos = 0; @last_inode = nil
    end
  end

  def check_for_new_lines
    new_lines = []
    unless @file_handle && !@file_handle.closed?
      initial_file_setup
      return [] unless @file_handle
    end

    current_stat = (File.stat(@log_file_path) rescue nil)

    if current_stat.nil?
      @file_handle.close; @file_handle = nil; @last_pos = 0; @last_inode = nil
      return []
    elsif current_stat.ino != @last_inode
      puts "LogTailer: rotation detected; re-reading new file."
      initial_file_setup
      if @file_handle
        @file_handle.seek(0); @last_pos = 0
        read_lines_from_current_pos(new_lines)
      end
      return new_lines
    elsif current_stat.size < @last_pos
      @file_handle.seek(0); @last_pos = 0
    end

    read_lines_from_current_pos(new_lines) if current_stat.size > @last_pos
    new_lines
  rescue => e
    puts "LogTailer: read error: #{e.message}"
    @file_handle&.close
    @file_handle = nil; @last_pos = 0; @last_inode = nil
    []
  end

  def close
    @file_handle.close if @file_handle && !@file_handle.closed?
    @file_handle = nil
  end

  private

  def read_lines_from_current_pos(lines_array)
    while (line = @file_handle.gets)
      lines_array << line.strip
    end
    @last_pos = @file_handle.pos
  end
end

# Efficiently read the last n non-empty lines of a (possibly huge) file by
# walking backwards in chunks — Cowrie logs run to tens of MB.
def tail_lines(path, n)
  return [] unless File.exist?(path)
  File.open(path, "rb") do |f|
    f.seek(0, IO::SEEK_END)
    pos = f.pos
    block = 65_536
    data = +""
    while pos > 0 && data.count("\n") <= n
      step = [block, pos].min
      pos -= step
      f.seek(pos)
      data = f.read(step) + data
    end
    data.split("\n").reject(&:empty?).last(n)
  end
rescue => e
  puts "tail_lines error: #{e.message}"
  []
end

# --- Classification --------------------------------------------------------
# Maps a Cowrie eventid to how the map should treat it. Events not listed are
# protocol chatter (kex, client.version, *.closed, ja4, …) and are skipped.
module Cowrie
  RENDER = {
    "cowrie.session.connect"        => { sev: "info",     cat: "connect", label: "Connect" },
    "cowrie.login.failed"           => { sev: "low",      cat: "login",   label: "Login failed" },
    "cowrie.login.success"          => { sev: "high",     cat: "breach",  label: "Login SUCCESS", flag: true },
    "cowrie.command.input"          => { sev: "high",     cat: "command", label: "Command" },
    "cowrie.command.failed"         => { sev: "medium",   cat: "command", label: "Command (failed)" },
    "cowrie.command.success"        => { sev: "high",     cat: "command", label: "Command" },
    "cowrie.session.file_download"  => { sev: "critical", cat: "malware", label: "Malware download", flag: true },
    "cowrie.session.file_upload"    => { sev: "critical", cat: "malware", label: "File upload", flag: true },
    "cowrie.direct-tcpip.request"   => { sev: "medium",   cat: "tunnel",  label: "Tunnel attempt" },
    "cowrie.telnet.exploit_attempt" => { sev: "critical", cat: "exploit", label: "Exploit attempt", flag: true },
  }.freeze

  module_function

  # Returns a short human detail string for an event (creds, command, file, …).
  def detail(entry, cat)
    case cat
    when "login", "breach"
      "#{entry["username"]}/#{entry["password"]}"
    when "command"
      trunc(entry["input"], 80)
    when "malware"
      entry["filename"] || entry["destfile"] || (entry["shasum"] && "sha256:#{entry["shasum"][0, 12]}…")
    when "tunnel"
      "#{entry["dst_ip"]}:#{entry["dst_port"]}"
    when "exploit"
      [entry["name"], entry["value"]].compact.join("=")
    when "connect"
      entry["protocol"]
    end
  end

  def trunc(s, n)
    s = s.to_s
    s.length > n ? "#{s[0, n]}…" : s
  end
end

# --- Geolocation -----------------------------------------------------------
module Geo
  module_function

  def private?(ip)
    return true if ip.nil? || ip.empty? || ip == "unknown"
    return true if ip =~ /\A127\.|\A10\.|\A192\.168\.|\A169\.254\./
    return true if ip =~ /\A172\.(1[6-9]|2\d|3[01])\./
    return true if ip == "::1" || ip =~ /\Afe80|\Afc|\Afd/i
    false
  end

  def scatter(ip)
    h = ip.to_s.each_byte.reduce(0) { |a, b| (a * 31 + b) & 0xffffffff }
    {
      lat: (((h % 12000) / 100.0) - 60.0).round(3),
      lon: ((((h >> 11) % 36000) / 100.0) - 180.0).round(3),
      country: "LAB", country_name: "Lab Network", city: "synthetic", lab: true,
    }
  end

  def locate(ip, reader, lab_mode)
    return (lab_mode ? scatter(ip) : nil) if private?(ip)
    begin
      rec = reader.city(ip)
      return (lab_mode ? scatter(ip) : nil) unless rec.location.latitude
      {
        lat: rec.location.latitude, lon: rec.location.longitude,
        country: rec.country.iso_code, country_name: rec.country.name,
        city: rec.city.name, lab: false,
      }
    rescue MaxMind::GeoIP2::AddressNotFoundError
      lab_mode ? scatter(ip) : nil
    rescue => e
      puts "GeoIP error for #{ip}: #{e.message}"
      nil
    end
  end
end

def normalize_time(ts)
  case ts
  when Numeric then Time.at(ts).utc
  when String
    if ts =~ /\A\d{9,}\z/ then Time.at(ts.to_i).utc else Time.parse(ts).utc end
  else Time.now.utc
  end
rescue
  Time.now.utc
end

# Convert a raw Cowrie event into a frontend-ready attack, or nil to skip.
def parse_entry(entry, reader, lab_mode)
  return nil unless entry.is_a?(Hash)
  spec = Cowrie::RENDER[entry["eventid"]]
  return nil unless spec               # protocol chatter — skip
  ip = entry["src_ip"]
  return nil unless ip
  geo = Geo.locate(ip, reader, lab_mode)
  return nil unless geo

  cat = spec[:cat]
  {
    ts: normalize_time(entry["timestamp"]).iso8601,
    ip: ip,
    lat: geo[:lat], lon: geo[:lon],
    country: geo[:country], country_name: geo[:country_name], city: geo[:city],
    lab: geo[:lab],
    severity: spec[:sev],
    type: spec[:label],
    category: cat,
    flag: spec[:flag] ? true : false,
    cve: entry["cve"],
    detail: Cowrie.detail(entry, cat),
    protocol: entry["protocol"],
    session: entry["session"],
    sensor: entry["sensor"],
    username: entry["username"],
    password: entry["password"],
    command: cat == "command" ? entry["input"] : nil,
  }
end

# --- Hub: ring buffer + live stats + SSE fan-out ---------------------------
class Hub
  def initialize(ring_size:, origin:)
    @mutex   = Mutex.new
    @subs    = []
    @ring    = []
    @ring_sz = ring_size
    @origin  = origin
    @next_id = 0
    @stats = {
      total: 0, flags: 0, lab: 0,
      severity: Hash.new(0), categories: Hash.new(0), countries: Hash.new(0),
      cves: Hash.new(0), usernames: Hash.new(0), passwords: Hash.new(0),
      commands: Hash.new(0),
    }
  end

  attr_reader :origin

  def record(attack, broadcast: true)
    @mutex.synchronize do
      @next_id += 1
      attack[:id] = @next_id
      @ring << attack
      @ring.shift while @ring.length > @ring_sz

      s = @stats
      s[:total] += 1
      s[:flags] += 1 if attack[:flag]
      s[:lab]   += 1 if attack[:lab]
      s[:severity][attack[:severity]]  += 1
      s[:categories][attack[:category]] += 1
      s[:countries][attack[:country_name] || attack[:country] || "Unknown"] += 1
      s[:cves][attack[:cve]] += 1 if attack[:cve]
      s[:usernames][attack[:username]] += 1 if attack[:username] && !attack[:username].empty?
      s[:passwords][attack[:password]] += 1 if attack[:password] && !attack[:password].empty?
      s[:commands][attack[:command]]   += 1 if attack[:command] && !attack[:command].empty?
    end
    broadcast("attack", attack) if broadcast
  end

  def recent_payload
    @mutex.synchronize { { origin: @origin, attacks: @ring.dup, stats: stats_unlocked } }
  end

  def stats_payload
    @mutex.synchronize { stats_unlocked }
  end

  def subscribe(socket)   = @mutex.synchronize { @subs << socket }
  def unsubscribe(socket) = @mutex.synchronize { @subs.delete(socket) }
  def subscriber?(socket) = @mutex.synchronize { @subs.include?(socket) }

  def broadcast(event, data)
    frame = "event: #{event}\ndata: #{JSON.generate(data)}\n\n"
    dead = []
    targets = @mutex.synchronize { @subs.dup }
    targets.each do |s|
      begin; s.write(frame); rescue; dead << s; end
    end
    unless dead.empty?
      @mutex.synchronize { dead.each { |s| @subs.delete(s) } }
      dead.each { |s| s.close rescue nil }
    end
  end

  def broadcast_stats = broadcast("stats", stats_payload)

  private

  def stats_unlocked
    c = @stats[:categories]
    {
      total: @stats[:total],
      flags: @stats[:flags],
      breaches: c["breach"], malware: c["malware"], commands: c["command"],
      logins: c["login"], connects: c["connect"], tunnels: c["tunnel"], exploits: c["exploit"],
      subscribers: @subs.length,
      severity: @stats[:severity],
      topCountries: top(@stats[:countries], 8),
      topCategories: top(@stats[:categories], 8),
      topUsernames: top(@stats[:usernames], 6),
      topPasswords: top(@stats[:passwords], 6),
      topCommands: top(@stats[:commands], 6),
      topCves: top(@stats[:cves], 6),
    }
  end

  def top(hash, n)
    hash.sort_by { |_, v| -v }.first(n).map { |k, v| { name: k, count: v } }
  end
end

# ============================================================================
#  Boot
# ============================================================================
config    = JSON.parse(File.read("config.json"))
lab_mode  = config.fetch("labMode", true)
ring_size = config.fetch("ringBuffer", 750)
backfill  = config.fetch("backfill", 300)
stats_int = config.fetch("statsIntervalSeconds", 3)
logfile   = config.fetch("logfile", "/tmp/cowrie.json")

reader = MaxMind::GeoIP2::Reader.new(database: "GeoLite2-City.mmdb")

origin = {
  lat:   config.dig("honeypot", "lat") || 40.7128,
  lon:   config.dig("honeypot", "lon") || -74.006,
  label: config.dig("honeypot", "label") || "Cowrie honeypot",
}

hub = Hub.new(ring_size: ring_size, origin: origin)

server = HoneySet.new(
  host: config["server"]["host"],
  port: config["server"]["port"],
  reverseProxy: false,
  # back.rb's parser reaches into configs["redactPublicIP"]; give it a real
  # (disabled) entry so request parsing doesn't fault on every header.
  configs: { "redactPublicIP" => { "enabled" => false } },
)

html       = File.read("web/attack-map.html")
world_json = File.read("web/world.json")

# --- Backfill: seed the ring buffer from the tail of the log (no broadcast) -
seeded = 0
tail_lines(logfile, backfill * 6).each do |line| # over-read; most events are skipped chatter
  begin
    attack = parse_entry(JSON.parse(line), reader, lab_mode)
    next unless attack
    hub.record(attack, broadcast: false)
    seeded += 1
  rescue JSON::ParserError
  rescue => e
    puts "Backfill: #{e.message}"
  end
end
puts "Backfill: seeded #{seeded} historical events from #{logfile}."

# --- Live tailer thread ----------------------------------------------------
tailer = LogTailer.new(logfile)
tail_thread = Thread.new do
  loop do
    lines = tailer.check_for_new_lines
    if lines.empty?
      sleep 0.4
    else
      lines.each do |line|
        begin
          attack = parse_entry(JSON.parse(line), reader, lab_mode)
          hub.record(attack) if attack
        rescue JSON::ParserError
        rescue => e
          puts "Tail parse error: #{e.message}"
        end
      end
    end
  end
rescue => e
  puts "Tailer thread died: #{e.message}\n#{e.backtrace.first(5).join("\n")}"
ensure
  tailer&.close
end
tail_thread.abort_on_exception = true

# --- Stats / heartbeat thread (keeps SSE connections alive) ----------------
stats_thread = Thread.new do
  loop do
    sleep stats_int
    begin; hub.broadcast_stats; rescue => e; puts "Stats broadcast error: #{e.message}"; end
  end
end
stats_thread.abort_on_exception = true

at_exit do
  tail_thread.exit
  stats_thread.exit
  tailer&.close
end

# --- HTTP routing ----------------------------------------------------------
SSE_HEADERS =
  "HTTP/1.1 200 OK\r\n" \
  "Content-Type: text/event-stream\r\n" \
  "Cache-Control: no-cache\r\n" \
  "Connection: keep-alive\r\n" \
  "X-Accel-Buffering: no\r\n" \
  "\r\n"

server.on(:request) do |id, socket, request|
  path = request[:path].to_s

  case
  when path == "/" || path.include?("index")
    socket.write(server.genReply(200, html, server.mimeFor(".html")))
    socket.close
  when path == "/world.json"
    socket.write(server.genReply(200, world_json, "application/json"))
    socket.close
  when path == "/api/recent"
    socket.write(server.genReply(200, hub.recent_payload.to_json, "application/json"))
    socket.close
  when path == "/api/stats"
    socket.write(server.genReply(200, hub.stats_payload.to_json, "application/json"))
    socket.close
  when path == "/api/stream"
    socket.write(SSE_HEADERS)
    socket.write(": connected\n\n")
    socket.write("event: recent\ndata: #{hub.recent_payload.to_json}\n\n")
    hub.subscribe(socket)
    # Do NOT close — HoneySet detects disconnect; on(:close) unsubscribes.
  else
    socket.write(server.genReply(404, %({"error":"not found"}), "application/json"))
    socket.close
  end
end

server.on(:close) do |id, socket, *_|
  hub.unsubscribe(socket) if hub.subscriber?(socket)
end

server.on(:error) do |id, socket, error|
  hub.unsubscribe(socket) if socket && hub.subscriber?(socket)
  msg = error.respond_to?(:message) ? error.message : error.to_s
  puts "Server error (id #{id}): #{msg}"
end

puts "Cowrie attack map live on http://#{config["server"]["host"]}:#{config["server"]["port"]}"
puts "  log: #{logfile} | lab mode: #{lab_mode} | ring: #{ring_size} | origin: #{origin[:label]}"
server.attach
