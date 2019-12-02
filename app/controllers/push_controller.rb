require "openssl"
require "base64"
require "stringio"
require "json"
require "fcm"
require "net/smtp"

class PushController < ApplicationController
  def push

    # crypto-key: dh=BLJQjupjQyujhTC--_5xRUgcBfAP_zINsAGTlaDuEME7s9TVgQYsyrzrgbt1vqScmZkoj4BWfPit6EzzaXDW02I;p256ecdsa=BDmWlrZ3gvcv0R7sBhaSp_99FRSC3bBNn9CElRvbcviwYwVPL1Z-G9srAJS6lv_pMe5IkTmKgBWUCNefnN3QoeQ
    crypto_key = request.headers["Crypto-Key"]
    render_object({ status: "fail", message: "invalid Crypto-Key" }, 500) and return if crypto_key.blank?

    sender_public_key = crypto_key.split(";")[0]
    render_object({ status: "fail", message: "invalid Crypto-Key" }, 500) and return if sender_public_key.blank?

    sender_public_key.gsub!(/^dh=/, "")

    salt = request.headers["Encryption"]
    if salt.blank? || !salt.start_with?("salt=")
      render_object({ status: "fail", message: "invalid salt" }, 500) and return
    end
    salt.gsub!(/^salt=/, "")

    payload = Base64.urlsafe_encode64(request.raw_post)
    decoded_payload = decode_payload(payload: payload, p256dh: sender_public_key, salt: salt)
    payload_json = JSON.parse(decoded_payload)

    puts payload_json

    Rails.logger.info("DBG:: body of message: #{payload_json}")

    deviceID = params[:id]
    account = params[:account]
    server = params[:server]
    deviceType = params[:device]
    puts deviceID
    fcm = FCM.new("AAAA0zIFHPE:APA91bHRzlX_JWApi2On48UmPlM7u0H8PH-yCsiJQHYr73c6CCijjNusnlrbR2SloeXi4sXjEglrZTJFjouvEjb-dyIzse3bhP8YEO-8KaTrdXhe941qjpypVvtnXqtQSS4yzYl0JhZS")
    # you can set option parameters in here
    #  - all options are pass to HTTParty method arguments
    #  - ref: https://github.com/jnunemaker/httparty/blob/master/lib/httparty.rb#L29-L60
    #  fcm = FCM.new("my_server_key", timeout: 3)

    registration_ids = [deviceID] # an array of one or more client registration tokens

    # See https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages for all available options.
    # options = { "notification": {
    #               "title": payload_json['title'],
    #               "body": payload_json['body']
    #           }
    # }

    #   options = { "android": {
    #     "data" => {
    #       "title": payload_json['title'],
    #       "body": payload_json['body'],
    #       "icon": payload_json['icon'],
    #       "notification_id": payload_json['notification_id',
    #       "notification_type": payload_json['notification_type'],
    #       "account": account,
    #       "server": server
    #     }
    # },
    # "apns" => {
    #   "title": payload_json['title'],
    #   "body": payload_json['body']
    # }
    # }

    # options = {
    #   "data": {
    #     "title":  payload_json['title'],
    #     "body": payload_json['body'],
    #     "icon": payload_json['icon'],
    #     "notification_id":  payload_json['notification_id'],
    #     "notification_type": payload_json['notification_type'],
    #     "account": account,
    #     "server": server
    #   }
    # }
    #   if params[:device]
    # options = {
    #   "message": {
    #     "token": deviceID,
    #     "notification": {
    #       "title": payload_json["title"],
    #       "body": payload_json["body"],
    #     },
    #     "data": {
    #       "title": payload_json["title"],
    #       "body": payload_json["body"],
    #       "notification_id": payload_json["notification_id"],
    #       "notification_type": payload_json["notification_type"],
    #       "account": account,
    #       "server": server,
    #     },
    #   },
    # }

    options = {
      "notification": {
        "title": payload_json["title"],
        "body": payload_json["body"],
        "sound": "defaul",
        "badge": "1",
      },
      "android":{
        "priority": "high"
      },
      "data": {
        "title": payload_json["title"],
        "body": payload_json["body"],
        "notification_id": payload_json["notification_id"],
        "notification_type": payload_json["notification_type"],
        "account": account,
        "server": server,
        "click_action": "FLUTTER_NOTIFICATION_CLICK",
      },
    }
    puts "THIS IS THE OPTIONS"
    puts options

    response = fcm.send(registration_ids, options)
    puts "The FCM RESPONSE:"
    puts response
    render plain: "success"
  end

  def decodeBase64(enc)
    Base64.urlsafe_decode64(enc)
  end

  class String
    def to_hex
      self.unpack("H*").join("")
    end
  end

  def decode_base64(enc)
    Base64.urlsafe_decode64(enc)
  end

  # Simplified HKDF, returning keys up to 32 bytes long
  def hkdf(salt, ikm, info, length)
    raise "Cannot return keys of more than 32 bytes, #{length} requested" if length > 32

    # Extract
    digest = OpenSSL::Digest.new("sha256")
    key_hmac = OpenSSL::HMAC.new(salt, digest)
    key_hmac.update(ikm)
    key = key_hmac.digest()

    # Expand
    info_hmac = OpenSSL::HMAC.new(key, digest)
    info_hmac.update(info)
    # A one byte long buffer containing only 0x01
    one_buffer = [1].pack("C")
    info_hmac.update(one_buffer)

    return info_hmac.digest().slice(0, length)
  end

  def create_info(type, client_public_key, server_public_key)
    # The start index for each element within the buffer is:
    # value               | length | start    |
    # -----------------------------------------
    # 'Content-Encoding: '| 18     | 0        |
    # type                | len    | 18       |
    # nul byte            | 1      | 18 + len |
    # 'P-256'             | 5      | 19 + len |
    # nul byte            | 1      | 24 + len |
    # client key length   | 2      | 25 + len |
    # client key          | 65     | 27 + len |
    # server key length   | 2      | 92 + len |
    # server key          | 65     | 94 + len |
    # For the purposes of push encryption the length of the keys will
    # always be 65 bytes.
    # info = Buffer.alloc(18 + len + 1 + 5 + 1 + 2 + 65 + 2 + 65)
    info = StringIO.new

    # The string 'Content-Encoding: ', as utf-8
    info << "Content-Encoding: "
    # The 'type' of the record, a utf-8 string
    info << type
    # A single null-byte
    info << "\0"
    # The string 'P-256', declaring the elliptic curve being used
    info << "P-256"
    # A single null-byte
    info << "\0"
    # The length of the client's public key as a 16-bit integer
    info << [client_public_key.length].pack("n")
    # Now the actual client public key
    info << client_public_key
    # Length of our public key
    info << [server_public_key.length].pack("n")
    # The key itself
    info << server_public_key

    return info.string
  end

  def decode_payload(payload:, p256dh:, salt:)
    server_auth_secret = decode_base64("T5bhIIyre5TDC1LyX4mFAQ==")
    server_public_key = decode_base64("BEpPCn0cfs3P0E0fY-gyOuahx5dW5N8quUowlrPyfXlMa6tABLqqcSpOpMnC1-o_UB_s4R8NQsqMLbASjnqSbqw=")
    server_private_key = decode_base64("ygY0_h2bMNRT5pB6xyGP84J_AW7LW76mu6svJfo3x2o=")

    client_salt = decode_base64(salt)
    client_public_key = decode_base64(p256dh)

    server_curve = OpenSSL::PKey::EC.generate("prime256v1")
    server_curve.private_key = OpenSSL::BN.new(server_private_key, 2)

    client_point = OpenSSL::PKey::EC::Point.new(server_curve.group, client_public_key)

    shared_secret = server_curve.dh_compute_key(client_point)

    auth_info = "Content-Encoding: auth\0"
    prk = hkdf(server_auth_secret, shared_secret, auth_info, 32)

    # Derive the Content Encryption Key
    content_encryption_key_info = create_info("aesgcm", server_public_key, client_public_key)
    content_encryption_key = hkdf(client_salt, prk, content_encryption_key_info, 16)

    # Derive the Nonce
    nonce_info = create_info("nonce", server_public_key, client_public_key)
    nonce = hkdf(client_salt, prk, nonce_info, 12)

    decipher = OpenSSL::Cipher.new("id-aes128-GCM")
    decipher.key = content_encryption_key
    decipher.iv = nonce

    payload = decode_base64(payload)
    result = decipher.update(payload)

    # remove padding and GCM auth tag
    pad_length = 0
    if result.bytes.length >= 3 && result.bytes[2] == 0
      pad_length = 2 + result.unpack("n").first
    end
    result = result.byteslice(pad_length, result.bytes.length - 16)

    # NOTE/TODO: The above condition is supposed to strip NUL byte padding, but it never
    # evaluates to true. I'm putting this in to manually strip any leading NUL bytes until
    # a cleaner solution and/or bug fix can be placed with the code above. /sf
    result.gsub!(/^(\u0000)+/, "")

    result
  end
end
