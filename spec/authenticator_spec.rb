require 'keylib'

Authenticator = KeyLib::CTAP2::Authenticator

RSpec.describe Authenticator do
  it "creating a Authenticator with default settings returns default settings with getInfo" do
    expected = "\xa5\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x31\x03\x50\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x04\xa5\x62\x72\x6b\xf4\x62\x75\x70\xf5\x64\x70\x6c\x61\x74\xf4\x70\x6d\x61\x6b\x65\x43\x72\x65\x64\x55\x76\x4e\x6f\x74\x52\x71\x64\xf4\x78\x1e\x6e\x6f\x4d\x63\x47\x61\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x73\x57\x69\x74\x68\x43\x6c\x69\x65\x6e\x74\x50\x69\x6e\xf4\x09\x81\x63\x75\x73\x62\x0a\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79".force_encoding("BINARY")

    auth = Authenticator.new
    info = auth.get_info

    expect(info).to eq expected
  end

  it "fetch information about the given authenticator using a cbor command" do
    expected = "\x00\xa5\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x31\x03\x50\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x04\xa5\x62\x72\x6b\xf4\x62\x75\x70\xf5\x64\x70\x6c\x61\x74\xf4\x70\x6d\x61\x6b\x65\x43\x72\x65\x64\x55\x76\x4e\x6f\x74\x52\x71\x64\xf4\x78\x1e\x6e\x6f\x4d\x63\x47\x61\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x73\x57\x69\x74\x68\x43\x6c\x69\x65\x6e\x74\x50\x69\x6e\xf4\x09\x81\x63\x75\x73\x62\x0a\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79".force_encoding("BINARY")

    auth = Authenticator.new

    expect(auth.cbor "\x04").to eq expected
  end
end
