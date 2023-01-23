class HashFunction {
public:
    virtual void Init() = 0;
    virtual void Update(const char* data, int len) = 0;
    virtual void Final(unsigned char* hash) = 0;
    virtual std::string ComputeFileHash(const char* file_name) = 0;
    virtual std::string ComputeStringHash(const std::string & plaintext) = 0;
};