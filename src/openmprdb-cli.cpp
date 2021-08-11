#include "gpgme.h"
#include <chrono>
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
#include "uuid.h"

using json = nlohmann::json;
using std::chrono::duration_cast;
using std::chrono::seconds;
using std::chrono::system_clock;

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
ABSL_FLAG(std::string, player_uuid, "", "");
ABSL_FLAG(double, points, -99, "");
ABSL_FLAG(std::string, comment, "", "");

// Required flags:
// - server_name
// - keyid
// - dburl
ABSL_FLAG(bool, reg, false, "Subcmd: register with remote server.");
// Required flags:
// - keyid
// - player_uuid
// - points
// - comment
ABSL_FLAG(bool, submit, false, "Subcmd: submit a new record.");
ABSL_FLAG(bool, list_servers, false, "Subcmd: list registered servers.");

// Naming convention: method name + API path
namespace restv1 {
struct ServerData {
    int64_t id;
    std::string uuid;
    std::string server_name;
    std::string key_id;
    std::string pubkey;
};

Result<json, std::string> CheckReply(cpr::Response &rsp) {
    json rsp_obj = json::parse(rsp.text);
    if (rsp.status_code >= 200 && rsp.status_code < 300 && rsp_obj["status"] == "OK") {
        return rsp_obj;
    }
    if (rsp_obj["reason"].is_string()) {
        return Err(rsp_obj["reason"]);
    } else {
        return Err("failed to parse reply: " + rsp.text);
    }
}

// Returns UUID or error message.
Result<std::string, std::string> PutServerRegister(std::string message,
                                                   std::string pubkey) {
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

    ASSIGN_OR_RAISE(json rsp_obj, CheckReply(rsp));
    return rsp_obj["uuid"];
}

// Returns UUID or error message.
Result<std::string, std::string> PutSubmitNew(const std::string &payload) {
    cpr::Response rsp = cpr::Put(
        cpr::Url{absl::GetFlag(FLAGS_dburl) + "/v1/submit/new"}, cpr::Body{payload},
        cpr::Header{{"Content-Type", "text/plain"},
                    {"User-Agent", "openmprdb-cli-cpp/0.0.0"}},
        cpr::DebugCallback([](cpr::DebugCallback::InfoType type, std::string data) {
            if (type == cpr::DebugCallback::InfoType::SSL_DATA_IN ||
                type == cpr::DebugCallback::InfoType::SSL_DATA_OUT)
                return;
            std::cout << data;
        }));
    std::cout << rsp.status_code << std::endl;
    std::cout << rsp.text << std::endl;

    ASSIGN_OR_RAISE(json rsp_obj, CheckReply(rsp));
    return rsp_obj["uuid"];
}

// Returns UUID or error message.
Result<std::string, std::string> DeleteServerUuid(const std::string &server_uuid,
                                                  const std::string &payload) {
    cpr::Response rsp = cpr::Delete(
        cpr::Url{absl::GetFlag(FLAGS_dburl) + "/v1/server/uuid/" + server_uuid},
        cpr::Body{payload},
        cpr::Header{{"Content-Type", "text/plain"},
                    {"User-Agent", "openmprdb-cli-cpp/0.0.0"}},
        cpr::DebugCallback([](cpr::DebugCallback::InfoType type, std::string data) {
            if (type == cpr::DebugCallback::InfoType::SSL_DATA_IN ||
                type == cpr::DebugCallback::InfoType::SSL_DATA_OUT)
                return;
            std::cout << data;
        }));
    std::cout << rsp.status_code << std::endl;
    std::cout << rsp.text << std::endl;

    ASSIGN_OR_RAISE(json rsp_obj, CheckReply(rsp));
    return rsp_obj["uuid"];
}

// Returns UUID or error message.
Result<std::string, std::string> DeleteSubmitUuid(const std::string &submit_uuid,
                                                  const std::string &payload) {
    cpr::Response rsp = cpr::Delete(
        cpr::Url{absl::GetFlag(FLAGS_dburl) + "/v1/submit/uuid/" + submit_uuid},
        cpr::Body{payload},
        cpr::Header{{"Content-Type", "text/plain"},
                    {"User-Agent", "openmprdb-cli-cpp/0.0.0"}},
        cpr::DebugCallback([](cpr::DebugCallback::InfoType type, std::string data) {
            if (type == cpr::DebugCallback::InfoType::SSL_DATA_IN ||
                type == cpr::DebugCallback::InfoType::SSL_DATA_OUT)
                return;
            std::cout << data;
        }));
    std::cout << rsp.status_code << std::endl;
    std::cout << rsp.text << std::endl;

    ASSIGN_OR_RAISE(json rsp_obj, CheckReply(rsp));
    return rsp_obj["uuid"];
}

Result<std::vector<ServerData>, std::string> GetServerList() {
    cpr::Response rsp = cpr::Get(cpr::Url{absl::GetFlag(FLAGS_dburl) + "/v1/server/list"},
                                 cpr::Header{{"User-Agent", "openmprdb-cli-cpp/0.0.0"}});
    ASSIGN_OR_RAISE(json rsp_obj, CheckReply(rsp));

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

    ASSIGN_OR_RAISE(std::string uuid, restv1::PutServerRegister(signed_payload, pubkey));
    std::cout << absl::StrFormat("Register name=%s,keyid=%s,dburl=%s,uuid=%s",
                                 server_name, keyid, absl::GetFlag(FLAGS_dburl), uuid)
              << std::endl;
    return 0;
}

Result<int, std::string> SubmitMain() {
    std::string keyid;
    ASSERT_OR_RAISE((keyid = absl::GetFlag(FLAGS_keyid)) != "");
    ASSIGN_OR_RAISE(KeyManager gpg, KeyManager::Init(keyid));

    std::string player_uuid = absl::GetFlag(FLAGS_player_uuid);
    double points = absl::GetFlag(FLAGS_points);
    ASSERT_OR_RAISE(!player_uuid.empty());
    ASSERT_OR_RAISE(points >= -1.0 && points <= 1.0);

    const uuids::uuid uuid = uuids::uuid_system_generator{}();
    long timestamp =
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count();

    std::string kv_str;
    absl::StrAppend(&kv_str, "uuid: ", uuids::to_string(uuid), "\n");
    absl::StrAppend(&kv_str, "timestamp: ", timestamp, "\n");
    absl::StrAppend(&kv_str, "player_uuid: ", player_uuid, "\n");
    absl::StrAppend(&kv_str, "points: ", points, "\n");
    absl::StrAppend(&kv_str, "comment: ", absl::GetFlag(FLAGS_comment));
    ASSIGN_OR_RAISE(std::string signed_kv, gpg.ClearSign(kv_str));
    std::cout << signed_kv << std::endl;
    ASSIGN_OR_RAISE(std::string reply_uuid, restv1::PutSubmitNew(signed_kv));
    std::cout << "Reply uuid = " << reply_uuid << std::endl;
    return 0;
}

int main(int argc, char *argv[]) {
    absl::SetProgramUsageMessage("placeholder");
    absl::ParseCommandLine(argc, argv);

    // Checks mutually exclusive args.
    int counter = 0;
    if (absl::GetFlag(FLAGS_reg))
        counter++;
    if (absl::GetFlag(FLAGS_submit))
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
    } else if (absl::GetFlag(FLAGS_submit)) {
        SubmitMain().Expect("");
    } else if (absl::GetFlag(FLAGS_list_servers)) {
        for (const auto &s : restv1::GetServerList().Expect("")) {
            std::cout << absl::StrFormat("%s:\n", s.uuid);
            std::cout << absl::StrFormat("  id:    %d\n", s.id);
            std::cout << absl::StrFormat("  name:  %s\n", s.server_name);
            std::cout << absl::StrFormat("  keyid: %s\n", s.key_id);
        }
    } else {
        std::cerr << "unreachable!" << std::endl;
    }
    return 0;
}
