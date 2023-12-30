require 'keylib'

class KeyLib::CTAP2::Authenticator
  
  # FIDO version identifiers  
  module Versions 
    # CTAP1/U2F authenticators
    U2F_V2 = "U2F_V2" 
    # CTAP2.0/FIDO2/WebAuthn authenticators
    FIDO_2_0 = "FIDO_2_0" 
    # CTAP2.1 preview features
    FIDO_2_1_PRE = "FIDO_2_1_PRE"
    # CTAP2.1/FIDO2/WebAuthn authenticators
    FIDO_2_1 = "FIDO_2_1"
    # CTAP2.2/FIDO2/WebAuthn authenticators
    FIDO_2_2 = "FIDO_2_2"
  end

  module Transport
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"
  end

  module Algorithm
    ES256 = {
      type: "public-key",
      alg: -7,
    }
  end
  
  # Default options. For a full list see https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetInfo. 
  DEFAULT_OPTIONS = {
    "plat" => false,
    "rk" => false,
    "up" => true,
    "noMcGaPermissionsWithClientPin" => false,
    "makeCredUvNotRqd" => false,
  }

  # Default authenticator settings. For a full list see https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetInfo. 
  DEFAULT_SETTINGS = {
    versions: [Versions::FIDO_2_1],
    aaguid: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".force_encoding("BINARY"),
    options: DEFAULT_OPTIONS,
    transports: [Transport::USB],
    algorithms: [Algorithm::ES256],
  }

  def initialize(
    settings = DEFAULT_SETTINGS
  )
    @settings = settings
  end
  
  # Return information about the authenticators capabilities.
  def get_info
    info = {}
    info[0x01] = @settings[:versions] if @settings.key?(:versions)
    info[0x02] = @settings[:extensions] if @settings.key?(:extensions)
    info[0x03] = @settings[:aaguid] if @settings.key?(:aaguid)
    info[0x04] = @settings[:options] if @settings.key?(:options)
    info[0x05] = @settings[:maxMsgSize] if @settings.key?(:maxMsgSize)
    info[0x06] = @settings[:pinUvAuthProtocols] if @settings.key?(:pinUvAuthProtocols)
    info[0x07] = @settings[:maxCredentialCountInList] if @settings.key?(:maxCredentialCountInList)
    info[0x08] = @settings[:maxCredentialIdLength] if @settings.key?(:maxCredentialIdLength)
    info[0x09] = @settings[:transports] if @settings.key?(:transports)
    info[0x0a] = @settings[:algorithms] if @settings.key?(:algorithms)
    info[0x0b] = @settings[:maxSerializedLargeBlobArray] if @settings.key?(:maxSerializedLargeBlobArray)
    info[0x0c] = @settings[:forcePINChange] if @settings.key?(:forcePINChange)
    info[0x0d] = @settings[:minPINLength] if @settings.key?(:minPINLength)
    info[0x0e] = @settings[:firmwareVersion] if @settings.key?(:firmwareVersion)
    info[0x0f] = @settings[:maxCredBlobLength] if @settings.key?(:maxCredBlobLength)
    info[0x10] = @settings[:maxRPIDsForSetMinPINLength] if @settings.key?(:maxRPIDsForSetMinPINLength)
    info[0x11] = @settings[:preferredPlatformUvAttempts] if @settings.key?(:preferredPlatformUvAttempts)
    info[0x12] = @settings[:uvModality] if @settings.key?(:uvModality)
    info[0x13] = @settings[:certifications] if @settings.key?(:certifications)
    info[0x14] = @settings[:remainingDiscoverableCredentials] if @settings.key?(:remainingDiscoverableCredentials)
    info[0x15] = @settings[:vendorPrototypeConfigCommands] if @settings.key?(:vendorPrototypeConfigCommands)
    info[0x16] = @settings[:attestationFormats] if @settings.key?(:attestationFormats)
    info[0x17] = @settings[:uvCountSinceLastPinEntry] if @settings.key?(:uvCountSinceLastPinEntry)
    info[0x18] = @settings[:longTouchForReset] if @settings.key?(:longTouchForReset)
    KeyLib::Cbor.encode info
  end
end


