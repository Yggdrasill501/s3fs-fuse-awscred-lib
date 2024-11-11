//
// created by: Filip Zitny on 2024-11-11
//
#ifndef AWS_WEBAPP_CRED_H_
#define AWS_WEBAPP_CRED_H_

#include <string>
#include "awscred.h"

extern "C" {
    const char* VersionS3fsCredential(bool detail);
    bool InitS3fsCredential(const char* popts, char** pperrstr);
    bool FreeS3fsCredential(char** pperrstr);
    bool UpdateS3fsCredential(char** ppaccess_key_id, char** ppserect_access_key,
                            char** ppaccess_token, long long* ptoken_expire, char** pperrstr);
}

class WebAppCredProvider {
private:
    static std::string webapp_url;
    static std::string access_token;

    static bool FetchCredentials(std::string& access_key_id,
                               std::string& secret_access_key,
                               std::string& session_token,
                               long long& expiration);

public:
    static void Initialize(const std::string& url, const std::string& token);
    static bool GetCredentials(std::string& access_key_id,
                             std::string& secret_access_key,
                             std::string& session_token,
                             long long& expiration);
};

#endif
