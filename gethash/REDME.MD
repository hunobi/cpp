# gethash

Program konsolowy wykorzystujący technologię CMake oraz bibliotekę OpenSSL do obliczania skrótu dla plików lub ciągu znaków. Program jest wieloplatformowy, oznacza to że dzięki CMake możemy zbudować go na dowolnej platformie.

## Informacje ogólne
```
Command structure:
        gethash <algorithm> <string|file> <plaintext|filepath>

Supported algorithms:
        sha1|sha256|sha512|md5|whirlpool

Examples:
        [1]     ./gethash sha256 string "Hello World"
        [2]     ./gethash sha512 file "../myBigFile.txt"

```

## Budowanie

Do zbudowania tego narzędzia potrzebne nam będą:
  * CMake w wersji minimum 3.15
  * Perl
  * Make
  * Kompilator C++ obsługujący standard C++ 17


Kroki:

1. W pierwszej kolejności wypada utworzyć katalog w którym chcemy zbudować nasz projekt. Zakładamy że jesteśmy w katalogu projektu.
   * `mkdir build`
   * `cd build`

2. W kolejnym kroku konfigurujemy projekt CMake:

   * Linux:
     * `cmake ..`

   * Windows:
      * `cmake .. -G"Unix Makefiles"`

3. W tym kroku będziemy budować projekt, dzięki czemu otrzymamy plik wykonywalny.
   * `make`

Proces budowania może trochę potrwać, głównie przez bibliotekę OpenSSL. Warto dodać, że Windows nie ma polecenia `make`, polecam zainstalować `mingw64` i tam doinstalować potrzebne paczki. Więcej informacji o tym programie: https://www.mingw-w64.org/
