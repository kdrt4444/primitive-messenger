#include <iostream>
#include <asio.hpp>
#include <thread>
#include <nlohmann/json.hpp>
#include <sodium.h>

using asio::ip::tcp;
using json = nlohmann::json;

unsigned char private_key[crypto_kx_SECRETKEYBYTES];
unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
unsigned char session_rx[crypto_kx_SESSIONKEYBYTES];
unsigned char session_tx[crypto_kx_SESSIONKEYBYTES];
bool keys_ready = false;
std::string my_name, peer_name;

std::string to_hex(const unsigned char* data, size_t len) {
    static const char* hex_chars = "0123456789abcdef";
    std::string hex;
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        hex.push_back(hex_chars[(data[i] >> 4) & 0xF]);
        hex.push_back(hex_chars[data[i] & 0xF]);
    }
    return hex;
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void read_loop(tcp::socket& socket) {
    try {
        char buf[2048];
        while (true) {
            std::size_t len = socket.read_some(asio::buffer(buf));
            std::string str(buf, len);

            try {
                json received = json::parse(str);

                if (received["type"] == "key_exchange") {
                    peer_name = received["from"];
                    auto peer_pub = hex_to_bytes(received["public_key"]);

                    bool is_client = my_name < peer_name;
                    int res = is_client ?
                        crypto_kx_client_session_keys(session_rx, session_tx, public_key, private_key, peer_pub.data()) :
                        crypto_kx_server_session_keys(session_rx, session_tx, public_key, private_key, peer_pub.data());

                    if (res == 0) {
                        keys_ready = true;
                        std::cout << "\n🔐 Ключи установлены с " << peer_name
                                  << (is_client ? " (client)" : " (server)") << "\n> ";
                    } else {
                        std::cerr << "❌ Ошибка генерации сессионных ключей\n";
                    }

                } else if (received["type"] == "message") {
                    if (!keys_ready) {
                        std::cout << "\n⚠️ Сообщение до установления ключей\n> ";
                        continue;
                    }

                    auto nonce = hex_to_bytes(received["nonce"]);
                    auto ciphertext = hex_to_bytes(received["ciphertext"]);

                    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
                    if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), nonce.data(), session_rx) == 0) {
                        std::string msg_str(decrypted.begin(), decrypted.end());
                        std::cout << "\n💬 " << peer_name << ": " << msg_str << "\n> ";
                    } else {
                        std::cout << "\n❌ Ошибка расшифровки сообщения\n> ";
                    }
                }
            } catch (...) {
                std::cout << "\n⚠️ Получено не-JSON сообщение: " << str << "\n> ";
            }

            std::cout.flush();
        }
    } catch (...) {
        std::cerr << "\n❌ Поток чтения завершён.\n";
    }
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        std::cerr << "❌ Введите адрес сервера к которому хотите подключится, например: ./run_client 127.0.0.1\n";
        return 1;
    }

    if (sodium_init() < 0) {
        std::cerr << "❌ libsodium не инициализирован\n";
        return 1;
    }

    asio::io_context io_context;
    tcp::socket socket(io_context);

    try {
        socket.connect(tcp::endpoint(asio::ip::make_address(argv[1]), 12345));

        crypto_kx_keypair(public_key, private_key);

        std::string peer;
        std::cout << "Введите ваше имя: ";
        std::getline(std::cin, my_name);
        std::cout << "Кому: ";
        std::getline(std::cin, peer);

        json hello;
        hello["name"] = my_name;
        hello["address"] = peer;
        hello["public_key"] = to_hex(public_key, crypto_kx_PUBLICKEYBYTES);
        asio::write(socket, asio::buffer(hello.dump()));

        std::thread(read_loop, std::ref(socket)).detach();

        while (true) {
            std::string msg;
            std::cout << "> ";
            std::getline(std::cin, msg);

            if (!keys_ready) {
                std::cout << "⌛ Ожидание установления ключей...\n";
                continue;
            }

            unsigned char nonce[crypto_secretbox_NONCEBYTES];
            randombytes_buf(nonce, sizeof(nonce));

            std::vector<unsigned char> ciphertext(msg.size() + crypto_secretbox_MACBYTES);
            crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char*>(msg.data()),
                                  msg.size(), nonce, session_tx);

            json out;
            out["type"] = "message";
            out["nonce"] = to_hex(nonce, sizeof(nonce));
            out["ciphertext"] = to_hex(ciphertext.data(), ciphertext.size());

            asio::write(socket, asio::buffer(out.dump()));
        }

    } catch (const std::exception& e) {
        std::cerr << "❌ Ошибка подключения или работы клиента: " << e.what() << "\n";
    }

    return 0;
}
