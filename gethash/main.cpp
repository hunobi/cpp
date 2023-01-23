#include <cstddef>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <string>
#include <cstring>
#include <memory>

#include <gethash/hash/hashfunction.hpp>
#include <gethash/hash/sha.hpp>
#include <gethash/hash/md5.hpp>
#include <gethash/hash/whirlpool.hpp>

using std::cout;
using std::endl;


std::string toLower(std::string input) {
    std::transform(input.begin(), input.end(), input.begin(), ::tolower);
    return input;
}

void set_object(std::string name, std::unique_ptr<HashFunction> & hasher){
    name = toLower(name);
    if(name == "sha1"){hasher= std::make_unique<HUB_SHA1>();}
    else if(name == "sha256"){hasher = std::make_unique<HUB_SHA256>();}
    else if(name == "sha512"){hasher = std::make_unique<HUB_SHA512>();}
    else if(name == "md5"){hasher = std::make_unique<HUB_MD5>();}
    else if(name == "whirlpool"){hasher = std::make_unique<HUB_WHIRLPOOL>();}
}

void help(){
    cout<< "\nCommand structure:\n\tgethash <algorithm> <string|file> <plaintext|filepath>\n"<<endl;
    cout<< "Supported algorithms:\n\tsha1|sha256|sha512|md5|whirlpool\n"<<endl;
    cout<< "Examples:\n\t[1]\t./gethash sha256 string \"Hello World\"\n\t[2]\t./gethash sha512 file \"../myBigFile.txt\"\n"<<endl;
}

int main(int argc, char *argv[]){

    // gethash <algorithm> <string|file> <plaintext|filepath>
    // algorithm :  sha1|sha256|sha512|md5|whirlpool
    
    if(argc < 4){
        help();
        return -1;
    }

    // algorithm | target | text or filepath
    std::string args [3] = { std::string(argv[1]), std::string(argv[2]), std::string(argv[3]) };

    std::unique_ptr<HashFunction> hasher = nullptr;
    set_object(args[0], hasher);

    if(hasher == nullptr){
        cout<< "Invalid hash algorithm!"<<endl;
        return -1;
    }
    
    if(args[1] == "string"){
        if(args[2].size() > 0){
            cout << args[0] <<":\t"<<hasher->ComputeStringHash(args[2]) << endl;
        }else{
            cout<< "The string cannot be empty!"<<endl;
        }
    }
    else if(args[1] == "file"){
        std::string ans = hasher->ComputeFileHash(args[2].c_str());
        if(ans != ""){
            cout << args[0] <<":\t"<<hasher->ComputeFileHash(args[2].c_str()) << endl;
        }
    }
    else{
        cout<< "Incorrect target!"<<endl;
    }

    return 0;
}