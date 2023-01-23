#include <openssl/sha.h>
#include <fstream>

class HUB_SHA1 : public HashFunction {
private:
    SHA_CTX ctx;
    const int DIGEST_LENGTH = SHA_DIGEST_LENGTH;
public:
    void Init() override {
        SHA1_Init(&ctx);
    }
    void Update(const char* data, int len) override {
        SHA1_Update(&ctx, data, len);
    }
    void Final(unsigned char* hash) override {
        SHA1_Final(hash, &ctx);
    }

    std::string ComputeFileHash(const char* file_name) override {
        std::ifstream file(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "The file could not be opened." << std::endl;
            return "";
        }
        this->Init();
        const int kBufferSize = 32768;
        char buffer[kBufferSize];
        while (file) {
            file.read(buffer, kBufferSize);
            this->Update(buffer, file.gcount());
        }

        unsigned char hash[DIGEST_LENGTH ];
        this->Final(hash);
        std::stringstream ss;
        for (int i = 0; i < DIGEST_LENGTH ; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    std::string ComputeStringHash(const std::string & plaintext) override {
        unsigned char hash[DIGEST_LENGTH ];
        this->Init();
        this->Update(plaintext.c_str(), plaintext.size());
        this->Final(hash);
        std::stringstream ss;
        for(int i = 0; i < DIGEST_LENGTH ; i++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
};


class HUB_SHA256 : public HashFunction {
private:
    SHA256_CTX ctx;
    const int DIGEST_LENGTH = SHA256_DIGEST_LENGTH;
public:
    void Init() override {
        SHA256_Init(&ctx);
    }
    void Update(const char* data, int len) override {
        SHA256_Update(&ctx, data, len);
    }
    void Final(unsigned char* hash) override {
        SHA256_Final(hash, &ctx);
    }

    std::string ComputeFileHash(const char* file_name) override {
        std::ifstream file(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "The file could not be opened." << std::endl;
            return "";
        }
        this->Init();
        const int kBufferSize = 32768;
        char buffer[kBufferSize];
        while (file) {
            file.read(buffer, kBufferSize);
            this->Update(buffer, file.gcount());
        }

        unsigned char hash[DIGEST_LENGTH];
        this->Final(hash);
        std::stringstream ss;
        for (int i = 0; i < DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    std::string ComputeStringHash(const std::string & plaintext) override {
        unsigned char hash[DIGEST_LENGTH];
        this->Init();
        this->Update(plaintext.c_str(), plaintext.size());
        this->Final(hash);
        std::stringstream ss;
        for(int i = 0; i < DIGEST_LENGTH; i++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
};

class HUB_SHA512 : public HashFunction {
private:
    SHA512_CTX ctx;
    const int DIGEST_LENGTH = SHA512_DIGEST_LENGTH;
public:
    void Init() override {
        SHA512_Init(&ctx);
    }
    void Update(const char* data, int len) override {
        SHA512_Update(&ctx, data, len);
    }
    void Final(unsigned char* hash) override {
        SHA512_Final(hash, &ctx);
    }

    std::string ComputeFileHash(const char* file_name) override {
        std::ifstream file(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "The file could not be opened." << std::endl;
            return "";
        }
        this->Init();
        const int kBufferSize = 32768;
        char buffer[kBufferSize];
        while (file) {
            file.read(buffer, kBufferSize);
            this->Update(buffer, file.gcount());
        }

        unsigned char hash[DIGEST_LENGTH];
        this->Final(hash);
        std::stringstream ss;
        for (int i = 0; i < DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    std::string ComputeStringHash(const std::string & plaintext) override {
        unsigned char hash[DIGEST_LENGTH];
        this->Init();
        this->Update(plaintext.c_str(), plaintext.size());
        this->Final(hash);
        std::stringstream ss;
        for(int i = 0; i < DIGEST_LENGTH; i++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
};