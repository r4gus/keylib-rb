require 'keylib'

CtapHid = KeyLib::CTAP2::Transports::CtapHid

RSpec.describe CtapHid do 
  it "allocates a new channel" do
    dev = CtapHid.new

    msg = "\xff\xff\xff\xff" # CID
    msg += "\x86" # CMD
    msg += "\x00\x08" # BCNT
    msg += "\x01\x02\x03\x04\x05\x06\x07\x08"
    msg.force_encoding("BINARY")

    response = dev.handle msg

    expect(response[:cmd]).to eq CtapHid::CTAPHID_INIT
    expect(response[:data][0..7]).to eq "\x01\x02\x03\x04\x05\x06\x07\x08".force_encoding("BINARY")
    expect(response[:data][13]).to eq "\xca".force_encoding("BINARY")
    expect(response[:data][14]).to eq "\xfe".force_encoding("BINARY")
    expect(response[:data][15]).to eq "\x01".force_encoding("BINARY")
    expect(response[:data][16]).to eq "\x0d".force_encoding("BINARY")
  end

  it "reject invalid channel id" do
    dev = CtapHid.new

    msg = "\xff\xff\xfe\xff" # invalid cid
    msg += "\x86" # CMD
    msg += "\x00\x08" # BCNT
    msg += "\x01\x02\x03\x04\x05\x06\x07\x08"
    msg.force_encoding("BINARY")

    response = dev.handle msg

    expect(response[:cmd]).to eq CtapHid::CTAPHID_ERROR
    expect(response[:data]).to eq "\x0b".force_encoding("BINARY")
  end

  it "only the init command can be issued over the broadcast channel" do
    dev = CtapHid.new

    msg = "\xff\xff\xfe\xff" # invalid cid
    msg += "\x90" # CMD (CBOR)
    msg += "\x00\x01" # BCNT 
    msg += "\x04" # CTAP2 getInfo
    msg.force_encoding("BINARY")

    response = dev.handle msg

    expect(response[:cmd]).to eq CtapHid::CTAPHID_ERROR
    expect(response[:data]).to eq "\x0b".force_encoding("BINARY")
  end

  context "with allocated channel" do
    before(:each) do
      @dev = CtapHid.new

      msg = "\xff\xff\xff\xff" # CID
      msg += "\x86" # CMD
      msg += "\x00\x08" # BCNT
      msg += "\x01\x02\x03\x04\x05\x06\x07\x08"
      msg.force_encoding("BINARY")

      response = @dev.handle msg
      @cid = response[:data][8..11]
    end 

    it "process a CBOR message" do
      msg = @cid
      msg += "\x90".force_encoding("BINARY") # CMD (CBOR)
      msg += "\x00\x01".force_encoding("BINARY") # BCNT 
      msg += "\x04".force_encoding("BINARY") # CTAP2 getInfo

      response = @dev.handle msg

      expect(response[:cmd]).to eq CtapHid::CTAPHID_CBOR
      expect(response[:cid]).to eq @cid
      expect(response[:data]).to eq "\x04"
    end
  end
end

CtapHidMessage = KeyLib::CTAP2::Transports::CtapHidMessage

RSpec.describe CtapHidMessage do 
  it "encodes 57 bytes into exactly one packet" do
    m = CtapHidMessage.new(0x06, "\x11\x22\x33\x44", "a" * 57)

    expected = [
      "\x11\x22\x33\x44\x86\x00\x39aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".force_encoding("BINARY"),
    ]
    
    i = 0
    m.each do |packet|
      expect(packet).to eq expected[i] 
      i += 1
    end

    expect(i).to eq 1 # only one iteration!
  end

  it "pad messages with 0x00 if required" do
    m = CtapHidMessage.new(0x06, "\x11\x22\x33\x44", "a" * 17)

    expected = [
      "\x11\x22\x33\x44\x86\x00\x11aaaaaaaaaaaaaaaaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".force_encoding("BINARY")
    ]
    
    i = 0
    m.each do |packet|
      expect(packet).to eq expected[i] 
      i += 1
    end

    expect(i).to eq 1 # only one iteration!
  end

  it "split large messages into multiple packets" do
    m = CtapHidMessage.new(0x10, "\xca\xfe\xba\xbe", "a" * 57 + "b" * 17)

    expected = [
      "\xca\xfe\xba\xbe\x90\x00\x4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".force_encoding("BINARY"),
      "\xca\xfe\xba\xbe\x00bbbbbbbbbbbbbbbbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".force_encoding("BINARY"),
    ]
    
    i = 0
    m.each do |packet|
      expect(packet).to eq expected[i] 
      i += 1
    end

    expect(i).to eq 2
  end

  it "encode a empty message" do
    m = CtapHidMessage.new(0x10, "\xca\xfe\xba\xbe", "")

    expected = [
      "\xca\xfe\xba\xbe\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".force_encoding("BINARY"),
    ]
    
    i = 0
    m.each do |packet|
      expect(packet).to eq expected[i] 
      i += 1
    end

    expect(i).to eq 1
  end

  it "a large message can lead to multiple continuation packets" do
    m = CtapHidMessage.new(0x10, "\xca\xfe\xba\xbe", "a" * 57 + "b" * 59 + "c" * 12)

    expected = [
      "\xca\xfe\xba\xbe\x90\x00\x80aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".force_encoding("BINARY"),
      "\xca\xfe\xba\xbe\x00bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".force_encoding("BINARY"),
      "\xca\xfe\xba\xbe\x01cccccccccccc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".force_encoding("BINARY"),
    ]
    
    i = 0
    m.each do |packet|
      expect(packet).to eq expected[i] 
      i += 1
    end

    expect(i).to eq 3
  end
end
