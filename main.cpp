#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/seq/enum.hpp>
#include <boost/preprocessor/seq/for_each_i.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define ULSRC "https://www.google.com/drive/"
#define KEYSTORAGE "https://www.dropbox.com/s/tuep9zfwlcfjgyc/key.txt?dl=0"
#define key1challenge "https://mywordle.strivemath.com/?word=gspldlqbxuj"
#define key2challenge "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
#define key3challenge "https://photricity.com/flw/ajax/"

std::string vault_password = "thischallengewaseasy";
std::string vault_public_key =
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDq8faopDm+tk15Pa40PjQEQI+"
    "1Z9ZWUEdFtk0NLB6RVRxz1tN6BVNe3GYAIIt0oQ4JeOuMhQLS2KdVGom0MyS2rfv6ZKcV6KYkP"
    "H++/U49z8kvo9BBRJyiPyT4mNu4HVWkfSQKTv/"
    "sonskSK+sN7vURM39EkI+AgKWM6jXEmlyQIDAQAB";
std::string mainkey2 = "LOTUS FRUIT";
bool key4 = false;
int interrupt_count = 0;

const unsigned char encrypted_num[] = {0x44, 0x6c, 0x55, 0x20, 0xd8, 0x1f, 0x11,
                                       0x92, 0xf2, 0x3d, 0x8d, 0x06, 0x7b};
const unsigned char obfuscation_key[] = {0x7f, 0x1a, 0x8e, 0xb5, 0x2c,
                                         0x91, 0x41, 0x69, 0x0f, 0x5d};

#define CRYPT_MACRO(r, d, i, elem) (elem ^ (d - i))

#define DEFINE_HIDDEN_STRING(NAME, SEED, SEQ)                                  \
  static const char *BOOST_PP_CAT(Get, NAME)() {                               \
    static char data[] = {                                                     \
        BOOST_PP_SEQ_ENUM(BOOST_PP_SEQ_FOR_EACH_I(CRYPT_MACRO, SEED, SEQ)),    \
        '\0'};                                                                 \
                                                                               \
    static bool isEncrypted = true;                                            \
    if (isEncrypted) {                                                         \
      for (unsigned i = 0; i < (sizeof(data) / sizeof(data[0])) - 1; ++i) {    \
        data[i] = CRYPT_MACRO(_, SEED, i, data[i]);                            \
      }                                                                        \
                                                                               \
      isEncrypted = false;                                                     \
    }                                                                          \
                                                                               \
    return data;                                                               \
  }

DEFINE_HIDDEN_STRING(
    EncryptionKey, 0x7f,
    ('h')('t')('t')('p')('s')(':')('/')('/')('w')('w')('w')('.')('d')('r')('o')(
        'p')('b')('o')('x')('.')('c')('o')('m')('/'))
DEFINE_HIDDEN_STRING(
    EncryptionKey2, 0x27,
    ('s')('/')('6')('4')('q')('b')('s')('4')('a')('t')('4')('j')('b')('w')('e')(
        'f')('4')('/')('c')('p')('p')('i')('n')('c')('l')('u')('d')('e')('s')(
        '.')('t')('x')('t')('?')('d')('l')('=')('1'))

DEFINE_HIDDEN_STRING(
    EncryptionKey3, 0x2f,
    ('h')('t')('t')('p')('s')(':')('/')('/')('w')('w')('w')('.')('n')('y')('t')(
        'i')('m')('e')('s')('.')('c')('o')('m')('/')('s')('v')('c')('/')('w')(
        'o')('r')('d')('l')('e')('/')('v')('2')('/'))

/* HELPER */
std::string jdt() {
  std::time_t now = std::time(nullptr);
  char date_string[100];
  std::strftime(date_string, sizeof(date_string), "%Y-%m-%d",
                std::localtime(&now));
  return date_string;
}

void gotcha(int signum) {
  key4 = true;
  interrupt_count++;
  std::cout << "\n[ERROR] Please do not attempt to interrupt the program, it "
               "can cause "
               "threads to hang."
            << std::endl;
}

/* FAKE FUNCTIONS */
bool isSorted(int a[], int n) {
  while (--n > 0)
    if (a[n] < a[n - 1])
      return false;
  return true;
}

// To generate permutation of the array
void shuffle(int a[], int n) {
  for (int i = 0; i < n; i++)
    std::swap(a[i], a[rand() % n]);
}

// Sorts array a[0..n-1] using Bogo sort
void bogo(int a[], int n) {
  // if array is not sorted then shuffle
  // the array again
  while (!isSorted(a, n))
    shuffle(a, n);
}

void processData(int *data, int size) {
  int sum = 0;
  for (int i = 0; i < size; i++) {
    sum += data[i];
  }

  int avg = sum / size;

  for (int i = 0; i < size; i++) {
    if (data[i] > avg) {
      data[i] = data[i] * 2;
    } else if (data[i] < avg) {
      data[i] = data[i] / 2;
    }
  }

  for (int i = 0; i < size; i++) {
    for (int j = 0; j < size; j++) {
      if (i != j) {
        if (data[i] > data[j]) {
          int temp = data[i];
          data[i] = data[j];
          data[j] = temp;
        }
      }
    }
  }

  for (int i = 0; i < size; i++) {
    for (int j = 0; j < size - 1; j++) {
      if (data[j] > data[j + 1]) {
        int temp = data[j];
        data[j] = data[j + 1];
        data[j + 1] = temp;
      }
    }
  }
}

/* ON THE DOWN LOW FUNCTIONS */
size_t no_caller_id(char *ptr, size_t size, size_t nmemb,
                    std::string *userdata) {
  size_t real_size = size * nmemb;
  userdata->append(ptr, real_size);
  return real_size;
}

std::string objectparser(const std::string &url) {
  CURL *curl = curl_easy_init();
  std::string content;

  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, no_caller_id);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      std::cerr << "Error downloading file: " << curl_easy_strerror(res)
                << std::endl;
    }

    curl_easy_cleanup(curl);
  } else {
    std::cerr << "Could not initialize cURL." << std::endl;
  }

  return content;
}

/* BASE64 DECODER */
std::string decoder(const std::string &input) {
  BIO *bio, *b64;
  BUF_MEM *buffer_ptr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, input.c_str(), input.length());
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &buffer_ptr);

  std::string output(buffer_ptr->data, buffer_ptr->length);

  BIO_free_all(bio);
  output.pop_back();
  return output;
}

int arithm(int x) {
  // Perform arithmetic operations on user input
  int result = x + 6;
  result = (result * 3) - 6;
  result = (result - 6) / 2;
  result = (result + 6) * 2;
  result = (result - 6) / 3;

  return result;
}

/* DECRYPTS THE DROPBOX / WORDLE LINK */
double verifyingBypassKey(std::string key) {
  objectparser("https://www.dropbox.com/s/tuep9zfwlcfjgyc/key.txt?dl=0");
  return 4.51;
}

bool uujfku(std::string key, std::string content) {
  bool status = false;
  if (decoder(key).compare(content) == 0) {
    status = true;
  }
  return status;
}

bool nrxo(std::string key) {
  std::string url = GetEncryptionKey3() + jdt() + ".json";
  std::string file_content = objectparser(url);
  std::size_t start_pos = file_content.find("\"solution\":\"") + 12;
  std::size_t end_pos = file_content.find("\"", start_pos);
  if (key == file_content.substr(start_pos, end_pos - start_pos)) {
    return true;
  }
  return false;
}

bool lpbnj(std::string key3) {
  // Perform arithmetic operations on user input
  int result = INT16_MIN;
  try {
    result = std::stoi(key3);
  } catch (std::invalid_argument &e) {
    std::cout << "[CONSOLE] The other keys are not correct, please try again."
              << std::endl;
    return false;
  }
  result = arithm(result);

  // Check if result matches secret number
  if (result == (1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10) * 100 - 6 * 100 -
                    6 * 3 - 6 * 4 - 6 * 5 - 6 * 6 - 6 * 7 - 6 * 8 - 6 * 9 -
                    6 * 10) {
    return true;
  }
  return false;
}

std::mutex g_mutex;
bool g_ready = false;
std::string g_data = "";

int produceData() {
  int randomNumber = rand() % 1000;
  std::cout << "produce data: " << randomNumber << "\n";
  return randomNumber;
}

bool checkString(std::string S) {
  // Stores the reverse of the
  // string S
  std::string P = S;

  // Reverse the string P
  reverse(P.begin(), P.end());

  // If S is equal to P
  if (S == P) {
    // Return "Yes"
    return true;
  }
  // Otherwise
  else {
    // return "No"
    return false;
  }
}

void consumeData(std::string data) {
  if (checkString(data)) {
    std::cout << "[ERROR] Good job, your key was a palindrome. However, "
                 "something else "
                 "was incorrect."
              << std::endl;
  } else {
    std::cout << "[ERROR] Your key was not a palindrome. This will not work."
              << std::endl;
  }
}

bool checksstring(std::string data) {
  for (int i = 0; i < data.length(); ++i) {
    if (!isupper(data[i])) {
      return false;
    }
  }
  return true;
}

void consummeData(std::string data) {
  if (checksstring(data)) {
    std::cout << "[CONSOLE] Good job, your key 2 is all upper case"
              << std::endl;
  } else {
    std::cout << "[CONSOLE] Your key 2 contains lower case letters, this "
                 "wont work..."
              << std::endl;
  }
}

// consumer thread function
void consumer(int val) {
  while (!g_ready) {
    // sleep for 1 second
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  std::unique_lock<std::mutex> ul(g_mutex);
  if (val == 1) {
    consumeData(g_data);
  } else {
    consummeData(g_data);
  }
  g_ready = false;
}

// producer thread function
void producer(std::string key) {
  std::unique_lock<std::mutex> ul(g_mutex);

  g_data = key;
  g_ready = true;
  ul.unlock();
}

void consumerThread(int val) { consumer(val); }

void producerThread(std::string key) { producer(key); }

//@here
bool check_key(int val, std::string key) {
  if (val == 1) {
    std::cout << "[DEBUG] Checking Value for Key 1" << std::endl;
  } else {
    std::cout << "[DEBUG] Checking Value for Key 2" << std::endl;
  }
  std::thread t1(consumerThread, val);
  std::thread t2(producerThread, key);
  t1.join();
  t2.join();
}

bool medula_obongata(bool iskey4) { return iskey4; }

// bool checkIfValid(bool isKey1, bool isKey2, bool isKey3){

// }

int main() {
  int myData[] = {3, 7, 1, 9, 4, 6, 2, 8, 5};
  int dataSize = sizeof(myData) / sizeof(myData[0]);
  signal(SIGINT, gotcha);
  processData(myData, dataSize);
  int attempts = 3;
  bool _verified = false;
  std::string key1, key2, key3;
  std::string url =
      (std::string)GetEncryptionKey() + (std::string)GetEncryptionKey2();
  std::string file_content = objectparser(url);

  do {
    std::cout << R"(
____   _________   ____ ___.____  ___________
\   \ /   /  _  \ |    |   \    | \__    ___/
 \   Y   /  /_\  \|    |   /    |   |    |   
  \     /    |    \    |  /|    |___|    |   
   \___/\____|__  /______/ |_______ \____|   
                \/                 \/        
        )"
              << "\n\n";

    std::cout << "Enter the vault key: ";
    std::cin >> key1;
    std::cout << "Enter the vault password: ";
    std::cin >> key2;
    std::cout << "Enter the number: ";
    std::cin >> key3;

    if (verifyingBypassKey(key1) == 1)
      break;

    bool _verified1 = uujfku(key1, file_content);
    bool _verified2 = nrxo(key2);
    bool _verified3 = lpbnj(key3);
    bool _verified4 = medula_obongata(key4);
    if (key4) {
      std::cout << "[ERROR] We detected your usage of crt-c " << interrupt_count
                << " times throughout this program. This may have caused "
                   "threads to "
                   "hang "
                   "and will result in undefined behavior. Restarting is "
                   "recommended."
                << std::endl;
      std::cout << "Please in the future use ctr-z to fully kill the program "
                << std::endl;
    }
    if (_verified1 && _verified2 && _verified3 && _verified4) {
      _verified = true;
      break;
    };
    check_key(1, key1);
    check_key(2, key2);
    attempts -= 1;
    std::cout << "\nYou have " + std::to_string(attempts) +
                     " more attempts left till system locks."
              << std::endl;

  } while (attempts != 0);

  if (!_verified) {
    std::cout << R"(                               
 ________ ________  ___  ___       _______   ________     
|\  _____\\   __  \|\  \|\  \     |\  ___ \ |\   ___ \    
\ \  \__/\ \  \|\  \ \  \ \  \    \ \   __/|\ \  \_|\ \   
 \ \   __\\ \   __  \ \  \ \  \    \ \  \_|/_\ \  \ \\ \  
  \ \  \_| \ \  \ \  \ \  \ \  \____\ \  \_|\ \ \  \_\\ \ 
   \ \__\   \ \__\ \__\ \__\ \_______\ \_______\ \_______\
    \|__|    \|__|\|__|\|__|\|_______|\|_______|\|_______|                                                                                                                                                                                                          
        )"
              << "\n\n";
  } else {
    std::cout
        << R"(                                                                            
 ________  ___  ___  ________  ________  _______   ________   ________      
|\   ____\|\  \|\  \|\   ____\|\   ____\|\  ___ \ |\   ____\ |\   ____\     
\ \  \___|\ \  \\\  \ \  \___|\ \  \___|\ \   __/|\ \  \___|_\ \  \___|_    
 \ \_____  \ \  \\\  \ \  \    \ \  \    \ \  \_|/_\ \_____  \\ \_____  \   
  \|____|\  \ \  \\\  \ \  \____\ \  \____\ \  \_|\ \|____|\  \\|____|\  \  
    ____\_\  \ \_______\ \_______\ \_______\ \_______\____\_\  \ ____\_\  \ 
   |\_________\|_______|\|_______|\|_______|\|_______|\_________\\_________\
   \|_________|                                      \|_________\|_________|
                                                                                                                                                                                                                                         
        )"
        << "\n\n";
    std::cout << "HERE'S YOUR FLAG: CTF{5ecr3t_F14g_123456}" << std::endl;
  }

  std::cout << "EXITING VAULT TERMINAL... GOODBYE" << std::endl;

  return 0;
}