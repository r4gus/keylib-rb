require "securerandom"

# The CTAPHID protocol builds on top of the USB HID (raw) protocol and
# allows the exchange of messages between a Client (e.g. web-browser) and
# and Authenticator over USB (see https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#usb-commands).
#
# @author David P. Sugar (r4gus)
class KeyLib::CTAP2::Transports::CtapHid
  
  # Timeout in milli seconds
  TIMEOUT = 250
  
  CTAPHID_MSG = 0x03
  CTAPHID_CBOR = 0x10
  CTAPHID_INIT = 0x06
  CTAPHID_PING = 0x01
  CTAPHID_CANCEL = 0x11
  CTAPHID_ERROR = 0x3f
  CTAPHID_KEEPALIVE = 0x3b
  CTAPHID_WINK = 0x08
  CTAPHID_LOCK = 0x04

  ERR_INVALID_CMD = 0x01
  ERR_INVALID_PAR = 0x02
  ERR_INVALID_LEN = 0x03
  ERR_INVALID_SEQ = 0x04
  ERR_MSG_TIMEOUT = 0x05
  ERR_CHANNEL_BUSY = 0x06
  ERR_LOCK_REQUIRED = 0x0a
  ERR_INVALID_CHANNEL = 0x0b
  ERR_OTHER = 0x7f
  
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
  #
  # This method will use the received packets to gradually build
  # a complete CTAPHID message. This message is then returned as
  # a Hash, containing the issued command (cmd), the related
  # channel id (cid), and the actual data (if available).
  #
  # Most Hashes can be directly serialized using CtapHidMessage and then send
  # back to the other device but there are a few responses that need a
  # special treatment:
  # - cmd == CTAPHID_MSG: The data field contains a CTAP1/U2F message for the authenticator. You should handle the message accordingly and then replace the data value with the actual response.
  # - cmd == CTAPHID_CBOR: The data field contains a CTAP2 message for the authenticator. You should handle the message accordingly and then replace the data value with the actual response.
  # - cmd == CTAPHID_CANCEL: You should cancel any ongoing transaction (e.g. terminate a thread that is currently processing a CTAP2 request).
  # - cmd == CTAPHID_WINK: Trigger some visual or audible identification (e.g. flash a LED, raise a application window to the foreground, create a popup message, ...).
  #
  # @param packet [String] a CTAPHID initialization or continuation packet.
  # @return [nil, Hash] either nil (if message is under construction), or a Hash.
  def handle(packet)
    if packet.encoding != Encoding::BINARY
      packet.force_encoding("BINARY") # we need a real string and not the unicode shit
    end

    if @begin != nil and (Time.now - @begin) * 1000.0 > TIMEOUT
      reset
    end

    if @data.length == 0 # init packet
      return error ERR_OTHER if packet.length < 7
      return error ERR_INVALID_CMD if packet.getbyte(4) & 0x80 == 0
      @cid = packet[0..3] # the first 4 bytes encode the Channel ID (CID)
      @begin = Time.now

      return error ERR_INVALID_CHANNEL if not is_broadcast? and not is_valid?(@cid)

      @cmd = packet.getbyte(4) & 0x7f
      @bcnt = packet[5..6].unpack("S>")[0]
      @data += packet[7..]
    else # cont packet
      return error ERR_OTHER if packet.length < 5
      return error ERR_INVALID_CMD if packet.getbyte(4) & 0x80 != 0
      return error ERR_CHANNEL_BUSY if packet[0..3] != @cid
      invalid_seq = @seq == nil and packet.getbyte(4) > 0 or @seq != nil and packet.getbyte(4) != @seq + 1
      return error ERR_INVALID_SEQ if invalid_seq

      @seq = packet.getbyte(4)
      @data += packet[5..]
    end

    if @data.length >= @bcnt
      return error ERR_INVALID_CHANNEL if (@cmd == 0x06 and not is_broadcast? and not is_valid?(@cid)) or (@cmd != 0x06 and not is_valid?(@cid))
    
      r = {}
      case @cmd
      when CTAPHID_PING
        r = { "cmd": @cmd, "cid": @cid, "data": @data }
      when CTAPHID_MSG
        r = { "cmd": @cmd, "cid": @cid, "data": @data }
      when CTAPHID_INIT
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

          r = { "cmd": @cmd, "cid": @cid, "data": init_response }
        else
          r = { "cmd": @cmd, "cid": @cid, "data": @cid }
        end
      when CTAPHID_CBOR
        r = { "cmd": @cmd, "cid": @cid, "data": @data }
      when CTAPHID_CANCEL
        r = { "cmd": @cmd, "cid": @cid }
      when CTAPHID_WINK
        r = { "cmd": @cmd, "cid": @cid }
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

  def error(reason)
    r = { "cmd": CTAPHID_ERROR, "cid": @cid != nil ? @cid : "\xff\xff\xff\xff", data: [reason].pack("C") } 
    reset
    r
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
