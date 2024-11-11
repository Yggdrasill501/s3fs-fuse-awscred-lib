//
// created by: Filip Zitny on 2024-11-11
//
#include <curl/curl.h>
#include <json/json.h>
#include "aws_webapp_cred.h"
#include <string.h>

std::string WebAppCredProvider::webapp_url;
std::string WebAppCredProvider::access_token;

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void WebAppCredProvider::Initialize(const std::string& url, const std::string& token) {
    webapp_url = url;
    access_token = token;
}

bool WebAppCredProvider::FetchCredentials(std::string& access_key_id,
                                        std::string& secret_access_key,
                                        std::string& session_token,
                                        long long& expiration) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    std::string url = webapp_url + "/api/aws-credentials";
    std::string response;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + access_token).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return false;
    }

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        return false;
    }

    access_key_id = root["AccessKeyId"].asString();
    secret_access_key = root["SecretAccessKey"].asString();
    session_token = root["SessionToken"].asString();
    expiration = root["Expiration"].asInt64();

    return true;
}

bool WebAppCredProvider::GetCredentials(std::string& access_key_id,
                                      std::string& secret_access_key,
                                      std::string& session_token,
                                      long long& expiration) {
    return FetchCredentials(access_key_id, secret_access_key, session_token, expiration);
}

// External interface implementation
extern "C" {
    const char* VersionS3fsCredential(bool detail) {
        static const char version[] = "WebApp AWS Credential Provider v1.0";
        static const char detail_version[] =
            "WebApp AWS Credential Provider v1.0\n"
            "Custom credential provider for fetching AWS credentials from webapp\n";
        return detail ? detail_version : version;
    }

    bool InitS3fsCredential(const char* popts, char** pperrstr) {
        if (!popts) {
            if (pperrstr) *pperrstr = strdup("Missing required options (webapp_url,access_token)");
            return false;
        }

        std::string opts(popts);
        size_t pos = opts.find(',');
        if (pos == std::string::npos) {
            if (pperrstr) *pperrstr = strdup("Invalid options format");
            return false;
        }

        std::string url = opts.substr(0, pos);
        std::string token = opts.substr(pos + 1);
        WebAppCredProvider::Initialize(url, token);
        return true;
    }

    bool FreeS3fsCredential(char** pperrstr) {
        return true;
    }

    bool UpdateS3fsCredential(char** ppaccess_key_id, char** ppserect_access_key,
                            char** ppaccess_token, long long* ptoken_expire, char** pperrstr) {
        std::string access_key_id, secret_access_key, session_token;
        long long expiration;

        if (!WebAppCredProvider::GetCredentials(access_key_id, secret_access_key,
                                              session_token, expiration)) {
            if (pperrstr) *pperrstr = strdup("Failed to fetch credentials from webapp");
            return false;
        }

        *ppaccess_key_id = strdup(access_key_id.c_str());
        *ppserect_access_key = strdup(secret_access_key.c_str());
        *ppaccess_token = strdup(session_token.c_str());
        *ptoken_expire = expiration;

        return true;
    }
}
