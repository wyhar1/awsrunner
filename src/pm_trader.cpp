// pm_trader.cpp
// Build: g++ -O2 -std=c++20 pm_trader.cpp -lssl -lcrypto -lpthread -lboost_system
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <chrono>

using json = nlohmann::json;
namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
namespace http = boost::beast::http;
using tcp      = asio::ip::tcp;

// This sender expects a pre-signed order JSON on stdin or via --order-file.
// It obtains L2 headers from a local Builder Signing Server: POST /sign-l2
//   body: {"method":"POST","path":"/order","body":<exact_request_body_string>}
// returns: { "headers": { "POLY_ADDRESS": "...", "POLY_API_KEY":"...", "POLY_PASSPHRASE":"...", "POLY_SIGNATURE":"...", "POLY_TIMESTAMP":"..." } }
// See: Builder Program & Authentication docs.
static json read_all_stdin(){
    std::ostringstream oss; oss << std::cin.rdbuf();
    return json::parse(oss.str());
}

static json http_json_post(const std::string& host, const std::string& port, const std::string& path,
                           const json& body, const std::vector<std::pair<std::string,std::string>>& extra_headers={},
                           bool tls=true){
    asio::io_context ioc;
    boost::beast::flat_buffer buffer;
    if(tls){
        ssl::context ctx(ssl::context::tlsv12_client);
        ctx.set_default_verify_paths();
        tcp::resolver r{ioc};
        auto results = r.resolve(host, port);
        boost::beast::tcp_stream tcp(ioc);
        tcp.connect(results);
        boost::beast::ssl_stream<boost::beast::tcp_stream> tls_stream(std::move(tcp), ctx);
        if(!SSL_set_tlsext_host_name(tls_stream.native_handle(), host.c_str())) throw std::runtime_error("SNI");
        tls_stream.handshake(ssl::stream_base::client);

        http::request<http::string_body> req{http::verb::post, path, 11};
        req.set(http::field::host, host);
        req.set(http::field::content_type, "application/json");
        for(auto& h: extra_headers) req.set(h.first, h.second);
        req.body() = body.dump();
        req.prepare_payload();
        http::write(tls_stream, req);
        http::response<http::string_body> res;
        http::read(tls_stream, buffer, res);
        if(res.result() != http::status::ok && res.result()!=http::status::accepted && res.result()!=http::status::created){
            throw std::runtime_error("HTTP "+std::to_string((int)res.result())+" "+res.body());
        }
        json j = json::parse(res.body());
        boost::system::error_code ec;
        tls_stream.shutdown(ec);
        return j;
    } else {
        tcp::resolver r{ioc};
        auto results = r.resolve(host, port);
        boost::beast::tcp_stream tcp(ioc);
        tcp.connect(results);
        http::request<http::string_body> req{http::verb::post, path, 11};
        req.set(http::field::host, host);
        req.set(http::field::content_type, "application/json");
        for(auto& h: extra_headers) req.set(h.first, h.second);
        req.body() = body.dump();
        req.prepare_payload();
        http::write(tcp, req);
        http::response<http::string_body> res;
        http::read(tcp, buffer, res);
        if(res.result() != http::status::ok && res.result()!=http::status::accepted && res.result()!=http::status::created){
            throw std::runtime_error("HTTP "+std::to_string((int)res.result())+" "+res.body());
        }
        return json::parse(res.body());
    }
}

int main(int argc, char** argv){a
    std::string clob_host = "clob.polymarket.com";
    std::string signer_host = "127.0.0.1";  // your Builder signing server (behind firewall)
    std::string signer_port = "8080";
    std::string order_file;
    json order; // pre-signed L1 order object (with signature)
    std::string owner_api_key; // set if your signing server doesn’t include it

    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        if(a=="--clob-host" && i+1<argc) clob_host=argv[++i];
        else if(a=="--signer-host" && i+1<argc) signer_host=argv[++i];
        else if(a=="--signer-port" && i+1<argc) signer_port=argv[++i];
        else if(a=="--order-file" && i+1<argc) order_file=argv[++i];
        else if(a=="--owner" && i+1<argc) owner_api_key=argv[++i];
    }

    try{
        if(!order_file.empty()){
            std::ifstream f(order_file);
            order = json::parse(std::string((std::istreambuf_iterator<char>(f)),{}));
        } else {
            // read JSON from stdin
            order = read_all_stdin();
        }
        if(!order.is_object() || !order.contains("order") || !order.contains("orderType")){
            std::cerr<<"Expected payload like {\"order\":{...signed fields...},\"owner\":\"<api-key>\",\"orderType\":\"GTC|FOK|GTD\"}\n";
            return 2;
        }

        json body = order;
        if(!owner_api_key.empty()) body["owner"] = owner_api_key;

        // 1) Ask the signing server for L2 headers (recommended by Builder docs)
        // NOTE: implement this endpoint in your signer: it must return the five L2 headers.
        json l2_req = {
            {"method","POST"},
            {"path", "/order"},
            {"body", body.dump()}
        };
        json l2 = http_json_post(signer_host, signer_port, "/sign-l2", l2_req, {}, /*tls*/false);
        if(!l2.contains("headers")||!l2["headers"].is_object()){
            throw std::runtime_error("sign-l2: missing headers");
        }
        std::vector<std::pair<std::string,std::string>> hdrs;
        for(auto& [k,v] : l2["headers"].items()){
            hdrs.push_back({k, v.get<std::string>()});
        }

        // 2) POST /order to CLOB with L2 headers (and your builder attribution headers if you use them)
        // See “Place Single Order” for payload & success schema.
        json resp = http_json_post(clob_host, "443", "/order", body, hdrs, /*tls*/true);
        std::cout << resp.dump() << std::endl;
    }catch(std::exception& e){
        std::cerr<<"ERR: "<<e.what()<<"\n";
        return 1;
    }
    return 0;
}

