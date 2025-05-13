#include <iostream>
#include <asio.hpp>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <nlohmann/json.hpp>

using asio::ip::tcp;
using json = nlohmann::json;

std::unordered_map<std::string, std::shared_ptr<tcp::socket>> clients;
std::unordered_map<std::string, std::vector<unsigned char>> public_keys;
std::mutex clients_mutex;

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byte_string.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string to_hex(const unsigned char* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        hex.push_back(hex_chars[(data[i] >> 4) & 0xF]);
        hex.push_back(hex_chars[data[i] & 0xF]);
    }
    return hex;
}

void handle_client(std::shared_ptr<tcp::socket> socket) {
    try {
        char data[2048];

        // Получаем имя, адресата и публичный ключ
        std::size_t len = socket->read_some(asio::buffer(data));
        std::string received(data, len);
        json data_json = json::parse(received);

        std::string name = data_json["name"];
        std::string address = data_json["address"];
        std::string hex_pub_key = data_json["public_key"];
        std::vector<unsigned char> public_key = hex_to_bytes(hex_pub_key);

        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients[name] = socket;
            public_keys[name] = public_key;

            if (public_keys.count(address)) {
                // Отправим адресату наш публичный ключ
                json notify_to_recipient = {
                    {"type", "key_exchange"},
                    {"from", name},
                    {"public_key", hex_pub_key}
                };
                asio::write(*clients[address], asio::buffer(notify_to_recipient.dump()));

                // Отправим нам публичный ключ адресата
                json notify_to_us = {
                    {"type", "key_exchange"},
                    {"from", address},
                    {"public_key", to_hex(public_keys[address].data(), public_keys[address].size())}
                };
                asio::write(*socket, asio::buffer(notify_to_us.dump()));
            }
        }

        std::cout << "[+] " << name << " подключился и будет писать " << address << "\n";

        // Обработка входящих сообщений
        for (;;) {
            len = socket->read_some(asio::buffer(data));
            std::string message(data, len);

            std::lock_guard<std::mutex> lock(clients_mutex);
            if (clients.count(address)) {
                asio::write(*clients[address], asio::buffer(message));
                std::cout << "[>] Переслано сообщение" << message <<" от " << name << " к " << address << "\n";
            } else {
                json error_msg = {
                    {"type", "error"},
                    {"message", "Пользователь " + address + " не в сети"}
                };
                asio::write(*socket, asio::buffer(error_msg.dump()));
            }
        }

    } catch (std::exception& e) {
        std::cerr << "[-] Ошибка/Отключение клиента: " << e.what() << "\n";
    }

    // Очистка данных клиента
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (auto it = clients.begin(); it != clients.end();) {
            if (it->second == socket) {
                std::cout << "[!] Клиент " << it->first << " отключился\n";
                public_keys.erase(it->first);
                it = clients.erase(it);
            } else {
                ++it;
            }
        }
    }
}

int main() {
    try {
        asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 12345));

        std::cout << "🚀 Сервер запущен на порту 12345\n";

        for (;;) {
            auto socket = std::make_shared<tcp::socket>(io_context);
            acceptor.accept(*socket);
            std::thread(handle_client, socket).detach();
        }

    } catch (std::exception& e) {
        std::cerr << "❌ Ошибка сервера: " << e.what() << std::endl;
    }

    return 0;
}
