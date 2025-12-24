#include <iostream>
#include <string>

using namespace std;

// Usamos long long para manejar bloques de números más grandes.
using BigNum = long long;

const int MAX_CAPACIDAD = 1000;

// TAMAÑO DEL BLOQUE:2 bytes. 
//El módulo 'n' (p*q) > 65535 !!!!!
const int BLOCK_SIZE = 2; 

class RSABlock {
private:
    BigNum privateKey_d;
    BigNum n;


    BigNum modPow(BigNum base, BigNum exp, BigNum mod) {
        BigNum res = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % mod;
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return res;
    }

    BigNum gcdExtended(BigNum a, BigNum b, BigNum &x, BigNum &y) {
        if (a == 0) { x = 0; y = 1; return b; }
        BigNum x1, y1;
        BigNum gcd = gcdExtended(b % a, a, x1, y1);
        x = y1 - (b / a) * x1;
        y = x1;
        return gcd;
    }

    BigNum modInverse(BigNum a, BigNum m) {
        BigNum x, y;
        BigNum g = gcdExtended(a, m, x, y);
        if (g != 1) return -1;
        return (x % m + m) % m;
    }

    BigNum gcd(BigNum a, BigNum b) {
        return (b == 0) ? a : gcd(b, a % b);
    }

public:
    BigNum publicKey_e;
    BigNum publicKey_n;

    RSABlock(BigNum p, BigNum q) {
        n = p * q;
        publicKey_n = n;
        BigNum phi = (p - 1) * (q - 1);

        publicKey_e = 3;
        while (gcd(publicKey_e, phi) != 1) publicKey_e += 2;
        privateKey_d = modInverse(publicKey_e, phi);
    }

    // --- ENCRIPTAR POR BLOQUES ---
    // letras a num por bloques
    void encrypt(string message, BigNum encryptedArray[], int &size) {
        size = 0;
        
        // padding necesario
        int paddingNeeded = 0;
        if (message.length() % BLOCK_SIZE != 0) {
            paddingNeeded = BLOCK_SIZE - (message.length() % BLOCK_SIZE);
        }

        // ' ' como relleno si necesario, para cumplir divisibilidad
        for(int k=0; k<paddingNeeded; k++) {
            message += ' '; 
        }

        for (int i = 0; i < message.length(); i += BLOCK_SIZE) {
            if (size >= MAX_CAPACIDAD) break;

            //Empaquetar
            BigNum blockValue = 0;
            for (int j = 0; j < BLOCK_SIZE; j++) {
                unsigned char c = message[i + j];
                // Desplazamos izq.
                blockValue = blockValue * 256 + c;
            }

            //Cifrar
            BigNum cipherNum = modPow(blockValue, publicKey_e, publicKey_n);
            
            //Save
            encryptedArray[size] = cipherNum;
            size++;
        }
    }

    // --- DESENCRIPTAR POR BLOQUES ---
    string decrypt(BigNum encryptedArray[], int size) {
        string decryptedFull = "";
        
        for (int i = 0; i < size; i++) {
            BigNum c = encryptedArray[i];
            
            //Descifrar al estilo RSA
            BigNum m = modPow(c, privateKey_d, n);

            //Desempaquetar
            char tempBlock[BLOCK_SIZE];
            
            for (int j = BLOCK_SIZE - 1; j >= 0; j--) {
                tempBlock[j] = (char)(m % 256); // Extraer último char
                m /= 256;                       // Quitar último char
            }

            // Añadir
            for (int j = 0; j < BLOCK_SIZE; j++) {
                decryptedFull += tempBlock[j];
            }
        }
        //El string resultante tendrá los espacios de relleno al final!!! TENER EN CUENTA
        return decryptedFull;
    }
};

int main() {
    // El módulo N (p*q) DEBE ser mayor que el bloque máximo!!!!!
    BigNum p = 307; 
    BigNum q = 313; 

    RSABlock rsa(p, q);

    cout << "--- RSA con Bloques (Block Size: " << BLOCK_SIZE << ") ---" << endl;
    cout << "Modulo N: " << rsa.publicKey_n << endl;

    // Mensaje con longitud impar para probar el Padding
    string mensaje = "Ingenieria!"; 
    cout << "Mensaje: [" << mensaje << "]" << endl;

    BigNum cifrado[MAX_CAPACIDAD];
    int lenCifrado = 0;

    rsa.encrypt(mensaje, cifrado, lenCifrado);

    cout << "Bloques Cifrados: ";
    for(int i = 0; i < lenCifrado; i++) {
        cout << cifrado[i] << " ";
    }
    cout << endl;
    cout << "(Fijate que hay menos numeros que letras, porque van agrupadas)" << endl;

    string descifrado = rsa.decrypt(cifrado, lenCifrado);
    cout << "Descifrado: [" << descifrado << "]" << endl;

    return 0;
}