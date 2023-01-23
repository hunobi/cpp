#include <openssl/whrlpool.h>
#include <fstream>

class HUB_WHIRLPOOL : public HashFunction {
private:
    WHIRLPOOL_CTX ctx;
    const int DIGEST_LENGTH = WHIRLPOOL_DIGEST_LENGTH ;
public:
    void Init() override {
        WHIRLPOOL_Init(&ctx);
    }
    void Update(const char* data, int len) override {
        WHIRLPOOL_Update(&ctx, data, len);
    }
    void Final(unsigned char* hash) override {
        WHIRLPOOL_Final(hash, &ctx);
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
