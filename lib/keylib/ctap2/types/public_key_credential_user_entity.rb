# Details about a user account.
#
# This data is provided with a `authenticatorMakeCredential` request.
#
# For more information see https://w3c.github.io/webauthn/#dictionary-user-credential-params.
class C2CC::CTAP2::Types::PublicKeyCredentialUserEntity
  # The user handle of the user account. A user handle is an opaque byte
  # sequence with a maximum size of 64 bytes, and is not meant to be
  # displayed to the user.
  attr_accessor :id
  # A human-palatable identifier for a user account. It is intended only for
  # display, i.e., aiding the user in determining the difference between user
  # accounts with similar displayNames. For example, "alexm",
  # "alex.mueller@example.com" or "+14255551234".
  attr_accessor :name
  # A human-palatable name for the user account, intended only for display.
  # For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let
  # the user choose this, and SHOULD NOT restrict the choice more than necessary.
  attr_accessor :displayName

  def initialize(args)
    id = args.fetch(:id) { |key| raise ArgumentError, "missing key #{key}" }
    name = args.fetch(:name) { |key| raise ArgumentError, "missing key #{key}" }
    displayName = args.fetch(:displayName) { |key| raise ArgumentError, "missing key #{key}" }
    raise ArgumentError, "id must be a BINARY String with a max length of 64 bytes" unless id.is_a?(String) and id.encoding == Encoding::BINARY and id.length <= 64
    raise ArgumentError, "name must be a String" unless name.is_a?(String)
    raise ArgumentError, "displayName must be a String", unless displayName.is_a?(String)

    @id = id
    @name = name
    @displayName = displayName
  end
end
