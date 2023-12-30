# CTAP2 Canonical CBOR En-/Decoder
#
# @author David P. Sugar (r4gus)
class KeyLib::Cbor
  # Encode a Ruby object into CBOR.
  #
  # @param obj [Integer, String, Symbol, Array, Hash] the Ruby object to serialize.
  # @return [String] a `BINARY` encoded CBOR `String`.
  def self.encode(obj)
    if obj.is_a? Integer
      if obj >= 0
        return enc 0, obj
      else
        return enc 0x20, -1 - obj
      end
    elsif obj.is_a? String
      if obj.encoding == Encoding::BINARY 
        return enc(0x40, obj.length) + obj
      else
        raw = obj.dup.force_encoding("BINARY")
        return enc(0x60, raw.length) + raw
      end
    elsif obj.is_a? Symbol
      encode obj.to_s
    elsif obj.is_a? Array
      obj.reduce(enc 0x80, obj.length) { |raw, v| raw + encode(v) }
    elsif obj.is_a? Hash
      # Sort the key-value pairs in lexographical order (usually there
      # are only Integers and Strings).
      #
      # We sort in the following order:
      # 1. Smaller major type sorts earlier (integer before string)
      # 2. Shorter string sorts before longer string
      # 3. the smaller value sorts befor the bigger value
      sorted = obj.sort do |a, b|
        if a[0].is_a?(String) and b[0].is_a?(Integer)
          -1
        elsif a[0].is_a?(Integer) and b[0].is_a?(String)
          1
        elsif a[0].is_a?(String) and b[0].is_a?(String)
          if a[0].length < b[0].length
            -1
          elsif a[0].length > b[0].length
            1
          else
            if a[0] < b[0]
              -1
            elsif a[0] == b[0]
              0
            else
              1
            end
          end
        else
          if a[0] < b[0]
            -1
          elsif a[0] == b[0]
            0
          else
            1
          end
        end
      end

      sorted.reduce(enc 0xa0, obj.length) do |raw, v| 
        raw + encode(v[0]) + encode(v[1])
      end
    elsif obj.is_a? TrueClass
      "\xf5".force_encoding("BINARY")
    elsif obj.is_a? FalseClass
      "\xf4".force_encoding("BINARY")
    end
  end
  
  # Decode CBOR into a Ruby object.
  #
  # This method is the inverse of (see #encode).
  #
  # @param raw [String] the raw CBOR data as `BINARY` encoded `String`.
  # @return [Integer, String, Symbol, Array, Hash] a Ruby object.
  def self.decode(raw)
    return decode2(raw)[0]
  end

  def self.decode2(raw, i: 0)
    raise ArgumentError.new "expected String but got #{raw.class.name}" if not raw.is_a?(String)
    cbor = raw.force_encoding("BINARY")
    raise ArgumentError.new "unexpected end of input at index #{i}" if cbor.length - i == 0  
  
    mt = cbor.getbyte(i) >> 5
    case mt
    when 0
      dec(cbor, i)
    when 1
      d = dec(cbor, i)
      [-d[0] - 1, d[1]]
    when 2..3
      length, offset = dec(cbor, i)
      raise ArgumentError.new "unexpected end of input at index #{cbor.length}. expected #{length} bytes but got #{cbor.length - offset}" if cbor.length < offset + length
      if mt == 2
        [cbor[offset..offset + length - 1].force_encoding("BINARY"), offset + length]
      else
        [cbor[offset..offset + length - 1].force_encoding("UTF-8"), offset + length]
      end
    when 4
      length, offset = dec(cbor, i)
      ret = []
      (1..length).step(1) do |n|
        v, offset = decode2 cbor, i: offset
        ret.append v
      end
      [ret, offset]
    when 5
      length, offset = dec(cbor, i)
      ret = {}
      (1..length).step(1) do |n|
        k, offset = decode2 cbor, i: offset
        v, offset = decode2 cbor, i: offset
        ret[k] = v
      end
      [ret, offset]
    when 6
      raise ArgumentError.new "major type 6 (tagged data items) currently not supported"
    when 7
      if cbor.getbyte(i) == 0xf4 
        [false, i + 1]
      elsif cbor.getbyte(i) == 0xf5
        [true, i + 1]
      else
        raise ArgumentError.new "major type 7, unsupported item"
      end
    end
  end

  private

  def self.dec(cbor, i)
    l = cbor.length - i # this has already been validated by decode
    ai = cbor.getbyte(i) & 0x1f 
    case ai
    when 0..23
      return[ai, i + 1]
    when 24..27
      length = 1 << (ai - 24)
      raise ArgumentError.new "unexpected end of input at index #{i}. expected #{1 + length} bytes but got #{l} bytes" if l < 1 + length
      case length
      when 1
        return [cbor.getbyte(i + 1), i + 2]
      when 2
        return [cbor[i + 1..i + 2].unpack("S>")[0], i + 3]
      when 4
        return [cbor[i + 1..i + 4].unpack("L>")[0], i + 5]
      when 8
        return [cbor[i + 1..i + 8].unpack("Q>")[0], i + 9]
      end
    else
      raise ArgumentError.new "invalid additional information #{ai} at index #{i}"
    end
  end

  def self.enc(h, v)
    case v
    when 0x00..0x17
      return [h | v].pack("C*")
    when 0x18..0xff
      return [h | 24, v].pack("C*")
    when 0x100..0xffff
      return [h | 25].pack("C*") + [v].pack("S>")
    when 0x10000..0xffffffff
      return [h | 26].pack("C*") + [v].pack("L>")
    when 0x100000000..0xffffffffffffffff
      return [h | 27].pack("C*") + [v].pack("Q>")
    else
      raise ArgumentError.new "number must fit in 8 bytes"
    end
  end
end
