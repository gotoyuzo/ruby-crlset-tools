require "open-uri"
require "openssl"
require "base64"
require "json"
require "nokogiri"
require "zip"

module CRLSet
  Host = "clients2.google.com"
  Path = "/service/update2/crx"
  AppId = "hfnkpimlhhgieaddgfemjhofmfblmnib"

  Gupdate = Struct.new(:protocol, :server, :daystart, :app)
  Daystart = Struct.new(:elapsed_days, :elapsed_seconds)
  App = Struct.new(:appid, :status, :updatecheck)
  Updatehceck = Struct.new(:codebase, :fp, :hash, :size, :status, :version)

  module_function

  def fetch
    url = request_url
    gupdate = fetch_update_info(url)
    crlset = fetch_crlset(gupdate)
    return crlset
  end

  def dump(crlset)
    header_len0 = 2
    header_len = crlset.unpack("v").first
    hdbytes = crlset[header_len0, header_len]
    header = JSON.parse(hdbytes)
    if header["ContentType"] != "CRLSet"
      raise "Unknown CRX content-type: #{header["ContetType"]}"
    elsif header["Version"] != 0
      raise "Unknown CRX version: #{header["Version"]}"
    end

    puts "Sequence: %d" % header["Sequence"]
    puts "Parents: %d" % header["NumParents"]
    puts

    len = header_len0 + header_len
    prefix_len = 32 + 4 # parent_spki_sha256(32chars) + num_serials(uint32le)
    header["NumParents"].times do |pcnt|
      prefix = crlset[len, prefix_len]
      len += prefix_len
      spki_hash, num_serials = prefix.unpack("a32V")
      puts "%s" % spki_hash.unpack("H*").first

      num_serials.times do |scnt|
        serial_len = crlset[len, 1].unpack("C").first
        len += 1
        serial = crlset[len, serial_len]
        len += serial_len
        puts "  %s" % serial.unpack("H*").first
      end
    end
  end

  ###################################

  def request_url()
    URI::Generic.build(
      scheme: "https",
      host: CRLSet::Host,
      path: CRLSet::Path,
      query: URI.encode_www_form(x: "id=%s&v=&uc" % [CRLSet::AppId])
    ).to_s
  end

  def fetch_update_info(url)
    data = open(url){|f| f.read }
    doc = Nokogiri::XML(data)
    doc.remove_namespaces!

    gnode = doc.xpath('gupdate[@protocol="2.0"]').first
    gupdate = Gupdate.new
    gupdate.protocol = gnode['protocol']
    gupdate.server = gnode['server']

    dnode = gnode.xpath('daystart').first
    gupdate.daystart = Daystart.new
    gupdate.daystart.elapsed_days = dnode['elapsed_days']
    gupdate.daystart.elapsed_seconds = dnode['elapsed_seconds']

    appnode = gnode.xpath('app').first
    gupdate.app = App.new
    gupdate.app.appid = appnode['appid']
    gupdate.app.status = appnode['status']

    chknode = appnode.xpath('updatecheck').first
    gupdate.app.updatecheck = Updatehceck.new
    gupdate.app.updatecheck.codebase = chknode['codebase']
    gupdate.app.updatecheck.fp = chknode['fp']
    gupdate.app.updatecheck.hash = chknode['hash']
    gupdate.app.updatecheck.size = chknode['size'].to_i
    gupdate.app.updatecheck.status = chknode['status']
    gupdate.app.updatecheck.version = chknode['version']

    return gupdate
  end

  def fetch_crlset(gupdate)
    puts "Downloading CRLSet version %d" % gupdate.app.updatecheck.version

    data = open(gupdate.app.updatecheck.codebase){|f| f.read }
    hash = Base64.encode64(Digest::SHA1.digest(data)).chomp
    if data.bytesize != gupdate.app.updatecheck.size.to_i ||
      hash != gupdate.app.updatecheck.hash
      raise "Downloaded data size or digest is mismatched"
    end

    magic, ver, pkeylen, siglen = data.unpack("a4VVV")
    hdlen = 16
    if magic != "Cr24" || int(ver) < 0 || int(pkeylen) < 0 || int(siglen) < 0
      raise "Downloaded file doesn't look like a CRX"
    end

    pkeybytes = data[hdlen, pkeylen]
    if pkeybytes.bytesize < pkeylen
      raise "Downloaded file doesn't look like a CRX"
    end

    sigbytes = data[hdlen + pkeylen, siglen]
    if sigbytes.bytesize < siglen
      raise "Downloaded file doesn't look like a CRX"
    end
    zipbytes = data[hdlen + pkeylen + siglen .. -1]

    pkey = OpenSSL::PKey::RSA.new(pkeybytes)
    unless pkey.verify(OpenSSL::Digest::SHA1.new, sigbytes, zipbytes)
      raise "Signature verification failure"
    end

    crlset = nil
    tmp = Tempfile.new("crlset")
    tmp.write(zipbytes)
    Zip::File.open(tmp.path) do |zip|
      entry = zip.get_entry("crl-set")
      crlset = entry.get_input_stream.read
    end

    return crlset
  end

  # convert from unsigned int32 into signed int32.
  def int(n)
    [n].pack("L").unpack("l")[0]
  end
end

if __FILE__ == $0
  case ARGV[0]
  when "fetch"
    File.open(ARGV[1], "w") do |f|
      f.write(CRLSet.fetch)
    end
  when "dump"
    data = File.read(ARGV[1])
    data.force_encoding("binary")
    CRLSet.dump(data)
  end
end
