// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <string_view>

namespace lume::crypto::known_answers {

inline constexpr std::string_view sha2_input =
    "616263";

inline constexpr std::string_view sha256_digest =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

inline constexpr std::string_view sha512_digest =
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
    "454d4423643ce80e2a9ac94fa54ca49f";

inline constexpr std::string_view hmac_key =
    "1e225cafb90339bba1b24076d4206c3e79c355805d851682bc818baa4f5a7779";

inline constexpr std::string_view hmac_message{};

inline constexpr std::string_view hmac_tag =
    "b175b57d89ea6cb606fb3363f2538abd73a4c00b4a1386905bac809004cf1933";

inline constexpr std::string_view hkdf_input_key =
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

inline constexpr std::string_view hkdf_salt =
    "000102030405060708090a0b0c";

inline constexpr std::string_view hkdf_info =
    "f0f1f2f3f4f5f6f7f8f9";

inline constexpr std::string_view hkdf_output =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

inline constexpr std::string_view x25519_secret_key =
    "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44";

inline constexpr std::string_view x25519_peer_public_key =
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";

inline constexpr std::string_view x25519_shared_secret =
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

inline constexpr std::string_view ed25519_seed =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

inline constexpr std::string_view ed25519_public_key =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

inline constexpr std::string_view ed25519_message{};

inline constexpr std::string_view ed25519_signature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
    "d25bf5f0595bbe24655141438e7a100b";

inline constexpr std::string_view aead_key =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

inline constexpr std::string_view aead_nonce =
    "404142434445464748494a4b4c4d4e4f5051525354555657";

inline constexpr std::string_view aead_associated_data =
    "50515253c0c1c2c3c4c5c6c7";

inline constexpr std::string_view aead_plaintext =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
    "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e";

inline constexpr std::string_view aead_ciphertext =
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39"
    "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
    "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49";

inline constexpr std::string_view mlkem_key_seed =
    "cbfc4405d1b2a3a386c94c25e0f2d5f5ee92cb0388ff4d6aa04223086d51c3fd24752da14c9fc3b8ae0d9e4a8b1016b8"
    "d8fc69e229c03ea2ef08a4ae0cffc37f";

inline constexpr std::string_view mlkem_public_key_sha256 =
    "67fe2cb60768d55758c67bfd5842692dedb14513d581c48db2cd3adf94568106";

inline constexpr std::string_view mlkem_ciphertext =
    "00e96c44eb5f5380d80b4cb05d608971a28fbe838b912b558bf9676c6c67c9692ed6ea063fc47b70d5d6004825c269b9"
    "cb8e68b5728d67f44844d97686a11154e3cbd4a6f9e47524d93d851bdce480d7762ded09be53d17cce3ee28dc5a06911"
    "c062b99b218355dd5822108c55e2c67f7ea0b74b6189b33b4589d8ff9d0c867d13edaaf1c5f724675320beda3e6acc67"
    "3c048fa04a1b30f899227d5a555e08a412a47b7db75eb118a8844a71b186880426f6bb6e77186d18e753cbcce93c9fb7"
    "6c729875b4d473eeca8dab9941969faef04df9ce3178e7341eab416d28bb7aee12bfb8f4c3df814eff45a0187329079a"
    "cfc41a8e8dba7b08d111f02e37a1d2b69e57eef808fcc6ae23385534a420a93dfb6a95c73e2f1016177c4fe9d3ced769"
    "e277293aaceded6d07efc7890eaa885bd1e73f9e5da2b9cfda0d44cbc9090705ac2ce3e7bcd7775b593c706e45ddc97d"
    "3a65d9b7e73673f9473df5bfec689671f73e7f6ee77c730a8ebda1f0b2c112a71904d6f28a51d8d479f8323fb485e722"
    "f5c4d5857e95989a9cbaf273efd04fc3cbde98baa9969e095e88accecfbd12ef2155497a5b15fe91a70d1106b91a5683"
    "63bfc2d6736cc8138cbc41ddf1e54fd40511e27d89e2c26c027b63c156e2bbb998faaed3d72186f0cc626dad39a782dc"
    "da2087fd13a9498e10b41b685646a227ea1166a5632c195983f4aba2b718b4074030d57126d34c38349892007acbea9e"
    "393b967dc3146b270f080a1f0bee90d65a095a6352a7718ed1717a8025a2bd38c66d120baf4247676a1fe044a57ce268"
    "c078f8ff46cc26fe4f9c7a03d6467adacb8418d26273662bce1f7bc00b906e0088e95dc0fb419e2232e85aac77b9e7cd"
    "563e604de5e1d3e9693dcd3b19865cf4250773691e7e0af9c2755cd31f49d1f96708f3ba2f0b98184525abb869e12d5c"
    "ea0ac1740181a875035300b05a54b8d42ee3b4ae92b06e43cd807e2b096c977f23c61ef8c989c52ed83754076dea1323"
    "f639250bef61bdf903bf7961cec89ba6942d9d0647ac9c8195d93ed8abcedf25754644035719a5a0a1c8c0798912726a"
    "9a8258e4c10ae7485322ed9ba331f6f090c4b492a4fcf53d753cd34f28ec0443fce0724f43c89a3942169d5099a8f743"
    "0f38691ebce2e3fe4f600d82c7ccedf60673f8e5d4c1a9f84b8b5b23f5ed63defb6a7205e0a8b105bdc6ff4568fc78cb"
    "4456b02fedb7f4c48f6fd6b69216a3319821039db40e19a31a0b0c9d471d5a7a73865d26f8be3595525b1ec4a8579efd"
    "07ea98e2602e2bffdfd8febc5c7b4c736d326b5030ccc6faf9420a9c156a8f4516b9fff675459dfdcd4ef85d7adbdffd"
    "60f4a39628e399cc752c2e99ab2f431dc765e7c9d206bfe32649fbef4ef48b1d7936fc74766d724350ee2245a8d5f23f"
    "bc6c7ed8b57168ce1e864e49d7f8c475dcda140bd42473825b3c72eb8c54780188813011e1962a503f9b516e13226de6"
    "375b204733b0192183c8f55e870e61cf8947c3191790bc0b657bc43aebc9d86c";

inline constexpr std::string_view mlkem_shared_secret =
    "76c10bb1d86d96d7eb18e298363e51f7728e113f455df7d15017940ed3541451";

}
