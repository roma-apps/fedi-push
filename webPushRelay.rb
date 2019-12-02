require "openssl"
require "base64"
require "stringio"
require "json"
require 'fcm'
require 'cgi'

def decodeBase64(enc)
  Base64.urlsafe_decode64(enc)
end

class String
  def to_hex
    self.unpack("H*").join("")
  end
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

def createInfo(type, client_public_key, server_public_key)
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

#############################################

# Authentication secret (auth_secret)
auth_secret = decodeBase64("DqtbDaxF1uP8B-Q7aRHp1g==")

# User agent public key (ua_public)
receiver_public = decodeBase64("BFSYMVrhpG8_3Xl3NX3yP3cjjTqr_EQ11nkNO4aFQDOEzS2jzcJN9ZUlGwG_g-jLmvd2m1cjPjNniBl3-9NfDfQ=")

# User agent private key (ua_private)
receiver_private = decodeBase64("5-zu_-dIV18S0BUT6I6n9wRbo2hhz0QmkcWTBPLv578=")

salt = decodeBase64("xoGfFhNGRayX5IwxmOoyVA")

# Application server public key (as_public)
# crypto-key header, dh portion
sender_public = decodeBase64("BOGH-MS1u9gUfns5BcEcq6tTjklel5pk2gcd8-Xl7Q9sAHwkHN8BJwklvd_W4LBdt-bte_sIfduTzQGpwNCExzs")

receiver_curve = OpenSSL::PKey::EC.generate("prime256v1")
receiver_curve.private_key = OpenSSL::BN.new(receiver_private, 2)
sender_point = OpenSSL::PKey::EC::Point.new(receiver_curve.group, sender_public)
shared_secret = receiver_curve.dh_compute_key(sender_point)

auth_info = "Content-Encoding: auth\0"
prk = hkdf(auth_secret, shared_secret, auth_info, 32)

# Derive the Content Encryption Key
contentEncryptionKeyInfo = createInfo("aesgcm", receiver_public, sender_public)
contentEncryptionKey = hkdf(salt, prk, contentEncryptionKeyInfo, 16)

# Derive the Nonce
nonceInfo = createInfo("nonce", receiver_public, sender_public)
nonce = hkdf(salt, prk, nonceInfo, 12)

body = decodeBase64("Uw1/j7Z1FUJOUiXRrcGVnHkfIuU9ZV7G47gafAoUZKcr2FtFBugycfb+ZwgPwDzBQYCxRgfJ6FjkYrIyLuGLAsJBEfvUGRUTIBGPXPnOlRnOIeEmkzxU02u91muTg+lewgQnaWp3Lm6FaIrWxuOPiO+SQL+OPXKWusjeEQCjWIiZL49oqKNs5K5lVN9z8Ai1H9Z0pOJVtujKFm/zVI5rSTAECbh8LcDeOGfkRgCzJaitgpjUqMxFT/vf7yTRSIia4Vy0gmuvzcW+iAyA9idYLSaCRTgHZxmpkjgMXkUEnFhNexa8D4HXc5JeoEEueDw3jFV38zzl296HseE6jjx2SvPpGUTLnV1f75CJ5Onsm1RUm1pYCVAS40qQJRpN7vMm")
#puts(body.to_hex)

decipher = OpenSSL::Cipher.new("id-aes128-GCM")
decipher.key = contentEncryptionKey
decipher.iv = nonce
result = decipher.update(body)

# remove padding and GCM auth tag
pad_length = 0
if result.bytes.length >= 3 && result.bytes[2] == 0
  pad_length = 2 + result.unpack("n").first
end
result = result.byteslice(pad_length, result.bytes.length - 16)

# strip padding
result.gsub!(/^(\u0000)+/,'')

result_json = JSON.parse(result)

puts result_json['body']
params = CGI.parse(URI.parse(url).query) 
deviceID = params["deviceToken"]
fcm = FCM.new("AAAADItJxDY:APA91bG0lgOQLyffd_NvQb_V1-IuW1SMz3lo5kdTQhSsJEVo_AxQQhsg1M6MeP6E6Xu1_OPyT1vkMxMy5bhYfBefZ_qesmJDAz4IVxs994Hws1JnvSw-BhGpFe3F-owkQ8TGRUd1zDpP")
# you can set option parameters in here
#  - all options are pass to HTTParty method arguments
#  - ref: https://github.com/jnunemaker/httparty/blob/master/lib/httparty.rb#L29-L60
#  fcm = FCM.new("my_server_key", timeout: 3)

registration_ids= [deviceID] # an array of one or more client registration tokens

# See https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages for all available options.
options = { "notification": {
              "title": result_json['title'],
              "body": result_json['body']
          }
}
response = fcm.send(registration_ids, options)

