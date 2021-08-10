#include "gpgme.h"
#include <iostream>
#include <memory>
#include <vector>

#include "absl/base/log_severity.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

#include "cpr/cpr.h"
#include "nlohmann/json.hpp"
#include "result.h"

using json = nlohmann::json;

#define LOG_AND_RAISE(err_expr)                                                          \
    do {                                                                                 \
        auto err_str = (err_expr);                                                       \
        std::string << absl::StrFormat("[%s:%d]%s", __FILE__, __LINE__, err_str);        \
        return Err(err_str);                                                             \
    } while (false)

#define ASSERT_OR_RAISE(predicate)                                                       \
    do {                                                                                 \
        bool success = (predicate);                                                      \
        if (!success) {                                                                  \
            std::string err_str = absl::StrFormat("ASSERTION_FAILED [%s:%d] %s",         \
                                                  __FILE__, __LINE__, #predicate);       \
            std::cerr << err_str << std::endl;                                           \
            return Err(err_str);                                                         \
        }                                                                                \
    } while (false)

ABSL_FLAG(std::string, dburl, "https://test.openmprdb.org",
          "database server to connect to");
ABSL_FLAG(std::string, keyid, "", "ID of the PGP key to use");
ABSL_FLAG(std::string, server_name, "", "");

// Required flags:
// - server_name
// - keyid
// - dburl
ABSL_FLAG(bool, reg, false, "Subcmd: register with remote server.");

ABSL_FLAG(bool, list_servers, false, "Subcmd: list registered servers.");

namespace restv1 {
struct ServerData {
    int64_t id;
    std::string uuid;
    std::string server_name;
    std::string key_id;
    std::string pubkey;
};

Result<std::string, std::string> ServerRegister(std::string message, std::string pubkey) {
    json obj = {{"message", message}, {"public_key", pubkey}};
    std::string payload = obj.dump(2, ' ', true);
    std::cout << payload << std::endl;

    cpr::Response rsp = cpr::Put(
        cpr::Url{absl::GetFlag(FLAGS_dburl) + "/v1/server/register"}, cpr::Body{payload},
        cpr::Header{{"Content-Type", "application/json"},
                    {"User-Agent", "openmprdb-cli-cpp/0.0.0"}},
        cpr::DebugCallback([](cpr::DebugCallback::InfoType type, std::string data) {
            if (type == cpr::DebugCallback::InfoType::SSL_DATA_IN ||
                type == cpr::DebugCallback::InfoType::SSL_DATA_OUT)
                return;
            std::cout << data;
        }));
    std::cout << rsp.status_code << std::endl;
    std::cout << rsp.text << std::endl;

    json rsp_obj = json::parse(rsp.text);
    if (rsp.status_code == 201 && rsp_obj["uuid"].is_string()) {
        return rsp_obj["uuid"];
    }
    if (rsp_obj["reason"].is_string()) {
        return Err(rsp_obj["reason"]);
    }
    return Err("Failed to parse rsp: " + rsp.text);
}

Result<std::vector<ServerData>, std::string> ServerList() {

    cpr::Response rsp = cpr::Get(cpr::Url{absl::GetFlag(FLAGS_dburl) + "/v1/server/list"},
                                 cpr::Header{{"User-Agent", "openmprdb-cli-cpp/0.0.0"}});

    json rsp_obj = json::parse(rsp.text);
    if (rsp.status_code != 200) {
        if (rsp_obj["reason"].is_string()) {
            return Err(rsp_obj["reason"]);
        }
        return Err("Failed to parse rsp: " + rsp.text);
    }

    std::vector<ServerData> ret;
    for (auto &server : rsp_obj["servers"]) {
        ret.push_back(ServerData{
            .id = server["id"],
            .uuid = server["uuid"],
            .server_name = server["server_name"],
            .key_id = server["key_id"],
            .pubkey = server["public_key"],
        });
    }
    return ret;
}
} // namespace restv1

class KeyManager {
  public:
    static Result<KeyManager, std::string> Init(std::string keyid) {
        KeyManager ret;

        // Check version
        const char *gpg_ver = gpgme_check_version(nullptr);
        std::cout << "GPGME version: " << gpg_ver << std::endl;
        ASSERT_OR_RAISE(gpgme_engine_check_version(GPGME_PROTOCOL_OPENPGP) ==
                        GPG_ERR_NO_ERROR);
        // Setup context
        ASSERT_OR_RAISE(gpgme_new(&ret.ctx_) == GPG_ERR_NO_ERROR);
        ASSERT_OR_RAISE(gpgme_set_protocol(ret.ctx_, GPGME_PROTOCOL_OPENPGP) ==
                        GPG_ERR_NO_ERROR);
        gpgme_set_armor(ret.ctx_, /*yes=*/true);
        // Select key
        ASSERT_OR_RAISE(gpgme_get_key(ret.ctx_, keyid.c_str(), &ret.key_,
                                      /*secret=*/true) == GPG_ERR_NO_ERROR);
        return ret;
    }

    KeyManager(const KeyManager &) = delete;
    KeyManager &operator=(const KeyManager &) = delete;
    KeyManager(KeyManager &&another) {
        std::swap(ctx_, another.ctx_);
        std::swap(key_, another.key_);
    }
    KeyManager &operator=(KeyManager &&another) {
        std::swap(ctx_, another.ctx_);
        std::swap(key_, another.key_);
        return *this;
    }
    ~KeyManager() {
        gpgme_key_release(key_);
        gpgme_release(ctx_);
    }

    Result<std::string, std::string> ExportPubkey() {
        gpgme_data_t key_data;
        ASSERT_OR_RAISE(gpgme_data_new(&key_data) == GPG_ERR_NO_ERROR);
        auto key_data_cleanup =
            absl::MakeCleanup([&key_data] { gpgme_data_release(key_data); });

        gpgme_key_t keys[2] = {key_, nullptr};
        ASSERT_OR_RAISE(gpgme_op_export_keys(ctx_, keys, 0, key_data) ==
                        GPG_ERR_NO_ERROR);
        ASSIGN_OR_RAISE(std::string key_data_str, ToString(key_data));
        return key_data_str;
    }

    Result<std::string, std::string> ClearSign(const std::string &data) {
        gpgme_data_t data_for_sign;
        gpgme_data_t data_sign_result;
        ASSERT_OR_RAISE(gpgme_data_new_from_mem(&data_for_sign, data.data(), data.size(),
                                                /*copy=*/false) == GPG_ERR_NO_ERROR);
        auto data_for_sign_cleanup =
            absl::MakeCleanup([&data_for_sign] { gpgme_data_release(data_for_sign); });
        ASSERT_OR_RAISE(gpgme_data_new(&data_sign_result) == GPG_ERR_NO_ERROR);
        auto data_sign_result_cleanup = absl::MakeCleanup(
            [&data_sign_result] { gpgme_data_release(data_sign_result); });

        ASSERT_OR_RAISE(gpgme_signers_add(ctx_, key_) == GPG_ERR_NO_ERROR);
        ASSERT_OR_RAISE(gpgme_op_sign(ctx_, data_for_sign, data_sign_result,
                                      GPGME_SIG_MODE_CLEAR) == GPG_ERR_NO_ERROR);
        ASSIGN_OR_RAISE(std::string sign_result_str, ToString(data_sign_result));
        return sign_result_str;
    }

  private:
    KeyManager() = default;
    gpgme_ctx_t ctx_ = nullptr;
    gpgme_key_t key_ = nullptr;

    Result<std::string, std::string> ToString(gpgme_data_t dh) {
        std::string ret;
        char buf[4096];
        ASSERT_OR_RAISE(gpgme_data_seek(dh, 0, SEEK_SET) == 0);
        while (true) {
            ssize_t red = gpgme_data_read(dh, buf, 4096);
            if (red < 0)
                RAISE_ERRNO("gpgme_data_read");
            if (red == 0) {
                return ret;
            }
            ret.append(buf, red);
        }
    }
};

Result<int, std::string> RegisterMain() {
    std::string keyid, server_name;
    ASSERT_OR_RAISE((keyid = absl::GetFlag(FLAGS_keyid)) != "");
    ASSERT_OR_RAISE((server_name = absl::GetFlag(FLAGS_server_name)) != "");
    ASSERT_OR_RAISE(absl::GetFlag(FLAGS_dburl) != "");

    std::string payload = "server_name: " + server_name;

    ASSIGN_OR_RAISE(KeyManager gpg, KeyManager::Init(keyid));
    ASSIGN_OR_RAISE(std::string pubkey, gpg.ExportPubkey());
    ASSIGN_OR_RAISE(std::string signed_payload, gpg.ClearSign(payload));

    ASSIGN_OR_RAISE(std::string uuid, restv1::ServerRegister(signed_payload, pubkey));
    std::cout << absl::StrFormat("Register name=%s,keyid=%s,dburl=%s,uuid=%s",
                                 server_name, keyid, absl::GetFlag(FLAGS_dburl), uuid)
              << std::endl;
    return 0;
}

int main(int argc, char *argv[]) {
    absl::SetProgramUsageMessage("placeholder");
    absl::ParseCommandLine(argc, argv);

    // Checks mutually exclusive args.
    int counter = 0;
    if (absl::GetFlag(FLAGS_reg))
        counter++;
    if (absl::GetFlag(FLAGS_list_servers))
        counter++;
    if (counter == 0) {
        std::cerr << "Missing subcmd argument." << std::endl;
        return 1;
    }
    if (counter > 1) {
        std::cerr << "Cannot have more than one subcmd argument." << std::endl;
        return 1;
    }

    if (absl::GetFlag(FLAGS_reg)) {
        RegisterMain().Expect("");
    } else if (absl::GetFlag(FLAGS_list_servers)) {
        for (const auto &s : restv1::ServerList().Expect("")) {
            std::cout << absl::StrFormat("%s:\n", s.uuid);
            std::cout << absl::StrFormat("  id:    %d\n", s.id);
            std::cout << absl::StrFormat("  name:  %s\n", s.server_name);
            std::cout << absl::StrFormat("  keyid: %s\n", s.key_id);
        }
    }
    return 0;
}