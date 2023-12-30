require "securerandom"

# The CTAPHID protocol builds on top of the USB HID (raw) protocol and
# allows the exchange of messages between a Client (e.g. web-browser) and
# and Authenticator over USB (see https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#usb-commands).
#
# @author David P. Sugar (r4gus)
class KeyLib::CTAP2::Transports::CtapHid
  
  # Timeout in milli seconds
  TIMEOUT = 250
  
  # Create a new CTAPHID instance.
  #
  # @param vmaj [String] major device version number.
  # @param vmin [String] minor device version number.
  # @param build [String] device build number.
  # @param wink [TrueClass, FalseClass] device supports the WINK function.
  # @param cbor [TrueClass, FalseClass] device supports the CBOR function.
  # @param nmsg [TrueClass, FalseClass] device DOES NOT support the MSG function.
  def initialize(
    vmaj = "\xca", 
    vmin = "\xfe", 
    build = "\x01", 
    wink = true,
    cbor = true,
    nmsg = true
  )
    @vmaj = vmaj.force_encoding("BINARY")
    @vmin = vmin.force_encoding("BINARY")
    @build = build.force_encoding("BINARY")
    @wink = wink
    @cbor = cbor
    @nmsg = nmsg
    @channels = []
    reset
  end
  
  # Check if the given CID represents the broadcast channel.
  def is_broadcast?
    @cid == "\xff\xff\xff\xff".force_encoding("BINARY")
  end
  
  # Check if the given CID is a valid channel.
  def is_valid?(cid)
    @channels.each do |channel| 
      if channel == cid
        return true
      end
    end

    false
  end
  
  # Handle a USB packet.
  def handle(packet)
    if packet.encoding != Encoding::BINARY
      packet.force_encoding("BINARY") # we need a real string and not the unicode shit
    end

    if @begin != nil and (Time.now - @begin) * 1000.0 > TIMEOUT
      reset
    end

    if @data.length == 0 # init packet
      if packet.length < 7
        reset
        return { "type": "error", "cmd": "\x3f",  data: "\x7f" } 
      end
      if packet.getbyte(4) & 0x80 == 0
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x01" } 
      end
      @cid = packet[0..3] # the first 4 bytes encode the Channel ID (CID)
      @begin = Time.now

      if not is_broadcast? and not is_valid?(@cid)
        return { "type": "error", "cmd": "\x3f", data: "\x0b" } 
      end

      @cmd = packet.getbyte(4) & 0x7f
      @bcnt = packet[5..6].unpack("S>")[0]
      @data += packet[7..]
    else # const packet
      if packet.length < 5
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x7f" } 
      end
      if packet.getbyte(4) & 0x80 != 0
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x01" } 
      end
      if packet[0..3] != @cid
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x06" } 
      end
      if @seq == nil and packet.getbyte(4) > 0 or @seq != nil and packet.getbyte(4) != @seq + 1
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x06" } 
      end

      @seq = packet.getbyte(4)
      @data += packet[5..]
    end

    if @data.length >= @bcnt
      if (@cmd == 0x06 and not is_broadcast? and not is_valid?(@cid))
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x0b" } 
      elsif @cmd != 0x06 and not is_valid?(@cid)
        reset
        return { "type": "error", "cmd": "\x3f", data: "\x0b" } 
      end
    
      r = {}
      case @cmd
      when 0x01 # ping
        r = { "type": "ping", "cmd": @cmd, "cid": @cid, "data": @data }
      when 0x03 # msg
        r = { "type": "msg", "cmd": @cmd, "cid": @cid, "data": @data }
      when 0x06 # init
        if is_broadcast?
          new_cid = SecureRandom.bytes(4)
          @channels.append new_cid

          flags = 0
          flags |= 1 if @wink
          flags |= 4 if @cbor
          flags |= 8 if @nmsg

          init_response = @data[0..7] # nonce
          init_response += new_cid
          init_response += "\x02" # version identifier
          init_response += @vmaj
          init_response += @vmin
          init_response += @build
          init_response += [flags].pack("C") 

          r = { "type": "init", "cmd": @cmd, "cid": @cid, "data": init_response }
        else
          r = { "type": "init", "cmd": @cmd, "cid": @cid, "data": @cid }
        end
      when 0x10 # cbor
        r = { "type": "cbor", "cmd": @cmd, "cid": @cid, "data": @data }
      when 0x11 # cancel
        r = { "type": "cancel", "cmd": @cmd, "cid": @cid }
      end
      
      reset
      return r
    end

    nil
  end

  private

  def reset
    @data = "".force_encoding("BINARY")
    @begin = nil
    @cid = nil
    @cmd = nil
    @seq = nil
  end
end

# Abstract representation of a CTAPHID message.
#
# This is a wrapper, around a BINARY encoded CTAPHID message String,
# that exposes a iterator via the each method.
#
# Each packet yielded by each is properly encoded (one initialization packet
# followed by n continuation packets) and can be transmitted directly via USB.
class KeyLib::CTAP2::Transports::CtapHidMessage
  
  IP_DATA_SIZE = 64 - 7
  CP_DATA_SIZE = 64 - 5
  
  # Create a new CtapHidMessage
  #
  # @param cmd [Integer] CTAPHID command code
  # @param cid [String] four byte channel ID that corresponds to the message
  # @param data [String] the data to encode
  def initialize(cmd, cid, data)
    @cmd = cmd
    @cid = cid.force_encoding("BINARY")
    @data = data.force_encoding("BINARY")
  end
  
  def each
    seq = 0
    i = 0
    first_round = true

    while i < @data.length or first_round
      packet = "".force_encoding("BINARY")

      if i == 0
        len = @data.length <= IP_DATA_SIZE ? @data.length : IP_DATA_SIZE

        packet += @cid
        packet += [0x80 | @cmd].pack("C")
        packet += [@data.length].pack("S>")
        packet += @data[0..len - 1]
        packet += "\x00" * (IP_DATA_SIZE - len)
      
        first_round = false
        i += len
      else
        len = @data.length - i <= CP_DATA_SIZE ? @data.length - i : CP_DATA_SIZE

        packet += @cid
        packet += [seq].pack("C")
        packet += @data[i..i + len - 1]
        packet += "\x00" * (CP_DATA_SIZE - len)

        i += len
        seq += 1
      end

      yield(packet)
    end
  end
end
