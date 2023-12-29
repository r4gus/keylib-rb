require 'keylib'

RSpec.describe KeyLib::Cbor, "#de-/serialize" do
  context "for major type 0 and 1" do
    test_vectors = [
      [0, "\x00"],
      [1, "\x01"],
      [10, "\x0a"],
      [23, "\x17"],
      [24, "\x18\x18"],
      [25, "\x18\x19"],
      [100, "\x18\x64"],
      [1000, "\x19\x03\xe8"],
      [1000000, "\x1a\x00\x0f\x42\x40"],
      [1000000000000, "\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00"],
      [18446744073709551615, "\x1b\xff\xff\xff\xff\xff\xff\xff\xff"],
      [-18446744073709551616, "\x3b\xff\xff\xff\xff\xff\xff\xff\xff"],
      [-1, "\x20"],
      [-10, "\x29"],
      [-100, "\x38\x63"],
      [-1000, "\x39\x03\xe7"],
    ]

    test_vectors.each do |v, exp| 
      it "serialize the integer #{v} into CBOR" do
        expect(KeyLib::Cbor.encode v).to eq exp.force_encoding("BINARY")
      end

      it "deserialize CBOR into #{v}" do
        expect(KeyLib::Cbor.decode exp).to eq v
      end
    end  
  end

  context "for major type 2 (byte string) and 3 (text string)" do
    test_vectors = [
      ["".force_encoding("BINARY"), "\x40"],
      ["\x01\x02\x03\x04".force_encoding("BINARY"), "\x44\x01\x02\x03\x04"],
      ["", "\x60"],
      ["a", "\x61\x61"],
      ["IETF", "\x64\x49\x45\x54\x46"],
      ["\"\\", "\x62\x22\x5c"],
      ["\u00fc", "\x62\xc3\xbc"],
      ["\u6c34", "\x63\xe6\xb0\xb4"],
    ]

    test_vectors.each do |v, exp, encoding| 
      it "serialize the string #{v} into CBOR" do
        expect(KeyLib::Cbor.encode v).to eq exp.force_encoding("BINARY")
      end

      it "deserialize CBOR into #{v}" do
        expect(KeyLib::Cbor.decode exp).to eq v
      end
    end  
  end

  context "for majort type 4 (array)" do
    test_vectors = [
      [[], "\x80"],
      [[1, 2, 3], "\x83\x01\x02\x03"],
      [[1, [2, 3], [4, 5]], "\x83\x01\x82\x02\x03\x82\x04\x05"],
      [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], "\x98\x19\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x18\x18\x19"],
    ]

    test_vectors.each do |v, exp| 
      it "serialize the array #{v} into CBOR" do
        expect(KeyLib::Cbor.encode v).to eq exp.force_encoding("BINARY")
      end

      it "deserialize CBOR into #{v}" do
        expect(KeyLib::Cbor.decode exp).to eq v
      end
    end  
  end

  context "for major type 5 (map)" do
    test_vectors = [
      [{}, "\xa0"],
      [{1 => 2, 3 => 4}, "\xa2\x01\x02\x03\x04"],
      [{"a" => 1, "b" => [2, 3]}, "\xa2\x61\x61\x01\x61\x62\x82\x02\x03"],
      [["a", {"b" => "c"}], "\x82\x61\x61\xa1\x61\x62\x61\x63"],
      [{"a" => "A", "b" => "B", "c" => "C", "d" => "D", "e" => "E"}, "\xa5\x61\x61\x61\x41\x61\x62\x61\x42\x61\x63\x61\x43\x61\x64\x61\x44\x61\x65\x61\x45"],
    ]

    test_vectors.each do |v, exp| 
      it "serialize the map #{v} into CBOR" do
        expect(KeyLib::Cbor.encode v).to eq exp.force_encoding("BINARY")
      end

      it "deserialize CBOR into #{v}" do
        expect(KeyLib::Cbor.decode exp).to eq v
      end
    end  
  end

  context "for simple values" do
    test_vectors = [
      [true, "\xf5"],
      [false, "\xf4"],
    ]

    test_vectors.each do |v, exp| 
      it "serialize  #{v} into CBOR" do
        expect(KeyLib::Cbor.encode v).to eq exp.force_encoding("BINARY")
      end

      it "deserialize CBOR into #{v}" do
        expect(KeyLib::Cbor.decode exp).to eq v
      end
    end  
  end
end
