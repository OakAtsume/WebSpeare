require "socket"
require "openssl"
require "thread"
require "securerandom"
require "json"
require "uri"
require_relative("../src/back") # Assuming HoneySet is defined here
require "maxmind/geoip2"
require "fileutils" # Added for LogTailer

# --- LogTailer Class (Copied from previous response) ---
# This class handles efficient reading of appended lines from a log file.
# It detects file rotation and truncation.
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
      @file_handle = File.open(@log_file_path, 'r')
      @file_handle.seek(0, IO::SEEK_END)
      @last_pos = @file_handle.pos
      @last_inode = File.stat(@log_file_path).ino
      puts "LogTailer: Initialized for '#{@log_file_path}' at position #{@last_pos}"
    rescue Errno::ENOENT
      @file_handle = nil
      @last_pos = 0
      @last_inode = nil
      puts "LogTailer: Log file '#{@log_file_path}' not found on init. Will try again."
    rescue => e
      puts "LogTailer: Error during initial file setup for '#{@log_file_path}': #{e.message}"
      @file_handle = nil
      @last_pos = 0
      @last_inode = nil
    end
  end

  def check_for_new_lines
    new_lines = []

    unless @file_handle && !@file_handle.closed?
      initial_file_setup
      return [] unless @file_handle
    end

    current_stat = begin
      File.stat(@log_file_path)
    rescue Errno::ENOENT
      nil
    end

    if current_stat.nil?
      puts "LogTailer: File disappeared! Resetting."
      @file_handle.close
      @file_handle = nil
      @last_pos = 0
      @last_inode = nil
      return []
    elsif current_stat.ino != @last_inode
      puts "LogTailer: File rotated! Re-opening and starting from beginning of new file."
      initial_file_setup
      if @file_handle
        @file_handle.seek(0)
        @last_pos = 0
        read_lines_from_current_pos(new_lines)
      end
      return new_lines
    elsif current_stat.size < @last_pos
      puts "LogTailer: File truncated! Resetting read position to beginning."
      @file_handle.seek(0)
      @last_pos = 0
    end

    if current_stat.size > @last_pos
      read_lines_from_current_pos(new_lines)
    end

    new_lines
  rescue => e
    puts "LogTailer: Error checking for new lines: #{e.message}"
    puts e.backtrace.join("\n")
    @file_handle&.close
    @file_handle = nil
    @last_pos = 0
    @last_inode = nil
    []
  end

  def close
    @file_handle.close if @file_handle && !@file_handle.closed?
    @file_handle = nil
    puts "LogTailer: File handle closed."
  end

  private

  def read_lines_from_current_pos(lines_array)
    while (line = @file_handle.gets)
      lines_array << line.strip
    end
    @last_pos = @file_handle.pos
  end
end
# --- End LogTailer Class ---


# --- Global Queue for Attacks (Thread-Safe) ---
# The log handler will push parsed attacks here, and the API endpoint will pop them.
ATTACK_QUEUE = Queue.new

# --- Configuration Loading ---
config = JSON.parse(File.read("config.json"))

# --- GeoIP2 Reader Setup ---
# This creates the Reader object which should be reused across lookups.
reader = MaxMind::GeoIP2::Reader.new(
  database: "GeoLite2-City.mmdb", # Ensure this file exists relative to your script
)

# --- HoneySet Server Setup ---
server = HoneySet.new(
  waf: {}, # Your WAF config if any
  host: config["server"]["host"],
  port: config["server"]["port"],
  reverseProxy: false,
)

# --- HTML Map Content (Loaded Once) ---
map_html_content = File.read("web/attack-map.html") # Renamed for clarity

# --- Log Handler Thread ---
log_tailer_instance = nil # Will hold the current LogTailer instance
current_log_date = nil    # To track which day's log file we're reading

handler_thread = Thread.new do
  loop do
    # Determine today's log file name
    today_date_str = Time.now.strftime(config["fileformat"])
    today_log_file_name = "#{config["logs"]}/#{today_date_str}.json"

    # Check if we need to switch log files (e.g., new day, or first run)
    if log_tailer_instance.nil? || current_log_date != today_date_str
      puts "Log Handler: Switching to log file: #{today_log_file_name}"
      log_tailer_instance&.close # Close previous file if open
      log_tailer_instance = LogTailer.new(today_log_file_name)
      current_log_date = today_date_str
    end

    # Get new lines from the current log file
    new_raw_log_lines = log_tailer_instance.check_for_new_lines

    if new_raw_log_lines.empty?
      # If no new lines, pause briefly before checking again
      # This prevents busy-waiting and allows IO.select in LogTailer to work
      sleep 0.5 # A short pause
    else
      # Process and parse each new log line
      new_raw_log_lines.each do |line|
        begin
          log_entry = JSON.parse(line)
          attack_data = parse_honeypot_log_entry(log_entry, reader)
          if attack_data
            ATTACK_QUEUE << attack_data # Push parsed attack to the shared queue
          end
        rescue JSON::ParserError => e
          puts "Log Handler: Failed to parse JSON line: #{line.inspect} - #{e.message}"
        rescue => e
          puts "Log Handler: Error processing log entry: #{e.message}"
          puts e.backtrace.join("\n")
        end
      end
    end
  end
rescue => e
  puts "Log Handler Thread experienced an unhandled error: #{e.message}"
  puts e.backtrace.join("\n")
ensure
  log_tailer_instance&.close # Ensure file is closed if thread exits
end

# Ensure the log handler thread stops when the main process exits
handler_thread.abort_on_exception = true # Crucial for debugging thread issues
at_exit do
  puts "Shutting down log handler thread..."
  handler_thread.exit # Politely ask the thread to exit
  log_tailer_instance&.close # Ensure file handle is closed
end

# --- Parsing Function for Honeypot Log Entries ---
# This function converts a raw JSON log entry into the format expected by the frontend.
def parse_honeypot_log_entry(log_entry, geoip_reader)
  # Basic check to ensure it's an "attack" worthy of display
  # You might refine this: e.g., only log entries with 'waf' true, or specific paths
  return nil unless log_entry["host"] && log_entry["timestamp"]

  ip = log_entry["host"] # Assuming 'host' field in log is the source IP
  
  # Attempt GeoIP lookup
  lat, lon, country_code = nil, nil, nil
  begin
    record = geoip_reader.city(ip)
    lat = record.location.latitude
    lon = record.location.longitude
    country_code = record.country.iso_code
  rescue MaxMind::GeoIP2::AddressNotFoundError
    puts "GeoIP: Address not found for #{ip}. Skipping." # Debugging
    return nil # Skip if IP not found in GeoIP database
  rescue => e
    puts "GeoIP Error for #{ip}: #{e.message}"
    return nil # Skip on other GeoIP errors
  end

  # Convert Unix timestamp to ISO 8601 string
  timestamp_iso = Time.at(log_entry["timestamp"]).utc.iso8601

  # Determine attack type and other info based on log entry
  # This is a simplified logic. You'll want to make this more sophisticated.
  attack_type = "Unknown"
  other_info = nil

  if log_entry["waf"]
    attack_type = log_entry["wafRule"]["name"] || "WAF Trigger"
    other_info = "Rule: #{log_entry["wafRule"]["regex"]}" if log_entry["wafRule"]["regex"]
  elsif log_entry["path"]
    case log_entry["path"].downcase
    when "/robots.txt" then attack_type = "Robots.txt Scan"
    when %r{/(phpmyadmin|admin|login|wp-admin|config\.php|git/config)}i
      attack_type = "Admin/Config Probe"
      other_info = "Path: #{log_entry["path"]}"
    when %r{/\.env}i then attack_type = ".env Leak Attempt"
    when %r{(sql|db|backup|dump)}i then attack_type = "Data Dump Probe"
    else
      attack_type = "Web Request"
      other_info = "Path: #{log_entry["path"]}"
    end
  end

  {
    lat: lat,
    lon: lon,
    timestamp: timestamp_iso,
    ip: ip,
    country: country_code,
    type: attack_type,
    other: other_info,
  }
end


# --- HoneySet Server Request Handlers ---
server.on(:request) do |id, socket, request|

  puts request
  # Front-end routing for map.html
  if request[:path] == "/" || request[:path].include?("index") # Corrected path check
    socket.write(
      server.reply(
        200,
        map_html_content, # Use the renamed variable
        server.mimeFor(".html")
      )
    )
    next
  end

  # API endpoint for fetching latest attacks
  if request[:path] == "/api/latest"
    attacks_to_send = []
    # Drain the queue: get all attacks that have accumulated since last request
    while !ATTACK_QUEUE.empty?
      attacks_to_send << ATTACK_QUEUE.pop
    end

    socket.write(
      server.reply(
        200,
        { attacks: attacks_to_send }.to_json,
        "application/json"
      )
    )
    # puts "API: Served #{attacks_to_send.size} new attacks." # Debugging
    next
  end

  # Add more handlers for other static assets if needed (e.g., CSS, JS)
  # Otherwise, HoneySet will handle unknown paths with default behavior (e.g., 404)
  # Example: For '/favicon.ico'
  # if request[:path] == "/favicon.ico"
  #   socket.write(server.reply(204, "", nil)) # No content for favicon
  #   next
  # end

  # Default Honeypot behavior for other requests
  # ... (your existing honeypot logic for other paths)
end

server.on(:error) do |id, socket, error|
  puts("HoneySet Error for ID #{id}:")
  puts(error)
  puts(error.backtrace.join("\n")) # Print full backtrace for better debugging
end

puts "HoneySet server starting on #{config["server"]["host"]}:#{config["server"]["port"]}"


server.attach()
