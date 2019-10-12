#include "cpr/session.h"

#include <algorithm>
#include <functional>
#include <string>
#include <iostream>

#include <curl/curl.h>

#include "cpr/curlholder.h"
#include "cpr/util.h"

namespace cpr {

class Session::Impl {
  public:
    Impl();

    CurlHolder* getHolder();

    void SetUrl(const Url& url);
    void SetParameters(const Parameters& parameters);
    void SetParameters(Parameters&& parameters);
    void SetHeader(const Header& header);
    void SetTimeout(const Timeout& timeout);
    void SetConnectTimeout(const ConnectTimeout& timeout);
    void SetAuth(const Authentication& auth);
    void SetDigest(const Digest& auth);
    void SetUserAgent(const UserAgent& ua);
    void SetPayload(Payload&& payload);
    void SetPayload(const Payload& payload);
    void SetProxies(Proxies&& proxies);
    void SetProxies(const Proxies& proxies);
    void SetMultipart(Multipart&& multipart);
    void SetMultipart(const Multipart& multipart);
    void SetRedirect(const bool& redirect);
    void SetMaxRedirects(const MaxRedirects& max_redirects);
    void SetCookies(const Cookies& cookies);
    void SetBody(Body&& body);
    void SetBody(const Body& body);
    void SetLowSpeed(const LowSpeed& low_speed);
    void SetVerbose(const Verbose& verbose);
    void SetVerifySsl(const VerifySsl& verify);
    void prepareRequest();
    void prepareRequest(CURL* curl);
    Response getResponse(CURLcode curl_error);
    Response getResponse(CURL* curl, CURLcode curl_error);

    Response Delete(bool do_request = true);
    Response Get(bool do_request = true);
    Response Head(bool do_request = true);
    Response Options(bool do_request = true);
    Response Patch(bool do_request = true);
    Response Post(bool do_request = true);
    Response Put(bool do_request = true);

  private:
    std::unique_ptr<CurlHolder, std::function<void(CurlHolder*)>> curl_;
    Url url_;
    Parameters parameters_;
    Proxies proxies_;

    Response makeRequest(CURL* curl);
    static void freeHolder(CurlHolder* holder);
    static CurlHolder* newHolder();

    //response string
    std::string response_string_;
    std::string resp_header_string_;
};

Session::Impl::Impl() {
    curl_ = std::unique_ptr<CurlHolder, std::function<void(CurlHolder*)>>(newHolder(),
                                                                          &Impl::freeHolder);
    auto curl = curl_->handle;
    if (curl) {
        // Set up some sensible defaults
        auto version_info = curl_version_info(CURLVERSION_NOW);
        auto version = std::string{"curl/"} + std::string{version_info->version};
        curl_easy_setopt(curl, CURLOPT_USERAGENT, version.data());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_->error);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
#ifdef CPR_CURL_NOSIGNAL
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
#endif
#if LIBCURL_VERSION_MAJOR >= 7
#if LIBCURL_VERSION_MINOR >= 25
#if LIBCURL_VERSION_PATCH >= 0
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
#endif
#endif
#endif
    }
}

void Session::Impl::freeHolder(CurlHolder* holder) {
    curl_easy_cleanup(holder->handle);
    curl_slist_free_all(holder->chunk);
    curl_formfree(holder->formpost);
    delete holder;
}

CurlHolder* Session::Impl::newHolder() {
    CurlHolder* holder = new CurlHolder();
    holder->handle = curl_easy_init();
    holder->chunk = NULL;
    holder->formpost = NULL;
    return holder;
}

CurlHolder* Session::Impl::getHolder() {
    return curl_.get();
}

void Session::Impl::SetUrl(const Url& url) {
    url_ = url;
}

void Session::Impl::SetParameters(const Parameters& parameters) {
    parameters_ = parameters;
}

void Session::Impl::SetParameters(Parameters&& parameters) {
    parameters_ = std::move(parameters);
}

void Session::Impl::SetHeader(const Header& header) {
    auto curl = curl_->handle;
    if (curl) {
        struct curl_slist* chunk = NULL;
        for (auto item = header.cbegin(); item != header.cend(); ++item) {
            auto header_string = std::string{item->first};
            if (item->second.empty()) {
                header_string += ";";
            } else {
                header_string += ": " + item->second;
            }

            auto temp = curl_slist_append(chunk, header_string.data());
            if (temp) {
                chunk = temp;
            }
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        curl_slist_free_all(curl_->chunk);
        curl_->chunk = chunk;
    }
}

void Session::Impl::SetTimeout(const Timeout& timeout) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout.Milliseconds());
    }
}

void Session::Impl::SetConnectTimeout(const ConnectTimeout& timeout) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout.Milliseconds());
    }
}

void Session::Impl::SetVerbose(const Verbose& verbose) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose.verbose);
    }
}

void Session::Impl::SetAuth(const Authentication& auth) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth.GetAuthString());
    }
}

void Session::Impl::SetDigest(const Digest& auth) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth.GetAuthString());
    }
}

void Session::Impl::SetUserAgent(const UserAgent& ua) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, ua.c_str());
    }
}

void Session::Impl::SetPayload(Payload&& payload) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.content.length());
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, payload.content.data());
    }
}

void Session::Impl::SetPayload(const Payload& payload) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.content.length());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.content.data());
    }
}

void Session::Impl::SetProxies(const Proxies& proxies) {
    proxies_ = proxies;
}

void Session::Impl::SetProxies(Proxies&& proxies) {
    proxies_ = std::move(proxies);
}

void Session::Impl::SetMultipart(Multipart&& multipart) {
    auto curl = curl_->handle;
    if (curl) {
        struct curl_httppost* formpost = NULL;
        struct curl_httppost* lastptr = NULL;

        for (auto& part : multipart.parts) {
            std::vector<struct curl_forms> formdata;
            formdata.push_back({CURLFORM_COPYNAME, part.name.data()});
            if (part.is_buffer) {
                formdata.push_back({CURLFORM_BUFFER, part.value.data()});
                formdata.push_back(
                        {CURLFORM_COPYCONTENTS, reinterpret_cast<const char*>(part.data)});
                formdata.push_back(
                        {CURLFORM_CONTENTSLENGTH, reinterpret_cast<const char*>(part.datalen)});
            } else if (part.is_file) {
                formdata.push_back({CURLFORM_FILE, part.value.data()});
            } else {
                formdata.push_back({CURLFORM_COPYCONTENTS, part.value.data()});
            }
            if (!part.content_type.empty()) {
                formdata.push_back({CURLFORM_CONTENTTYPE, part.content_type.data()});
            }
            formdata.push_back({CURLFORM_END, nullptr});
            curl_formadd(&formpost, &lastptr, CURLFORM_ARRAY, formdata.data(), CURLFORM_END);
        }
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        curl_formfree(curl_->formpost);
        curl_->formpost = formpost;
    }
}

void Session::Impl::SetMultipart(const Multipart& multipart) {
    auto curl = curl_->handle;
    if (curl) {
        struct curl_httppost* formpost = NULL;
        struct curl_httppost* lastptr = NULL;

        for (auto& part : multipart.parts) {
            std::vector<struct curl_forms> formdata;
            formdata.push_back({CURLFORM_PTRNAME, part.name.data()});
            if (part.is_buffer) {
                formdata.push_back({CURLFORM_BUFFER, part.value.data()});
                formdata.push_back({CURLFORM_BUFFERPTR, reinterpret_cast<const char*>(part.data)});
                formdata.push_back(
                        {CURLFORM_BUFFERLENGTH, reinterpret_cast<const char*>(part.datalen)});
            } else if (part.is_file) {
                formdata.push_back({CURLFORM_FILE, part.value.data()});
            } else {
                formdata.push_back({CURLFORM_PTRCONTENTS, part.value.data()});
            }
            if (!part.content_type.empty()) {
                formdata.push_back({CURLFORM_CONTENTTYPE, part.content_type.data()});
            }
            formdata.push_back({CURLFORM_END, nullptr});
            curl_formadd(&formpost, &lastptr, CURLFORM_ARRAY, formdata.data(), CURLFORM_END);
        }
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        curl_formfree(curl_->formpost);
        curl_->formpost = formpost;
    }
}

void Session::Impl::SetRedirect(const bool& redirect) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, std::int32_t(redirect));
    }
}

void Session::Impl::SetMaxRedirects(const MaxRedirects& max_redirects) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, max_redirects.number_of_redirects);
    }
}

void Session::Impl::SetCookies(const Cookies& cookies) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_COOKIELIST, "ALL");
        curl_easy_setopt(curl, CURLOPT_COOKIE, cookies.GetEncoded().data());
    }
}

void Session::Impl::SetBody(Body&& body) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, body.data());
    }
}

void Session::Impl::SetBody(const Body& body) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    }
}

void Session::Impl::SetLowSpeed(const LowSpeed& low_speed) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, low_speed.limit);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, low_speed.time);
    }
}

void Session::Impl::SetVerifySsl(const VerifySsl& verify) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
    }
}

Response Session::Impl::Delete(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 0L);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    return do_request? makeRequest(curl) : Response();
}

Response Session::Impl::Get(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    }

    return do_request? makeRequest(curl) : Response();
}

Response Session::Impl::Head(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, NULL);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }

    return do_request? makeRequest(curl) : Response();
}

Response Session::Impl::Options(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
    }

    return do_request? makeRequest(curl) : Response();
}

Response Session::Impl::Patch(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    }

    return do_request? makeRequest(curl) : Response();
}

Response Session::Impl::Post(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    }

    return do_request? makeRequest(curl) : Response();
}

Response Session::Impl::Put(bool do_request) {
    auto curl = curl_->handle;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    }

    return do_request? makeRequest(curl) : Response();
}

void Session::Impl::prepareRequest()
{
    auto curl = curl_->handle;
    prepareRequest(curl);
}
void Session::Impl::prepareRequest(CURL* curl)
{
    if(curl == NULL) return;

    if (!parameters_.content.empty()) {
        Url new_url{url_ + "?" + parameters_.content};
        curl_easy_setopt(curl, CURLOPT_URL, new_url.data());
    } else {
        curl_easy_setopt(curl, CURLOPT_URL, url_.data());
    }

    auto protocol = url_.substr(0, url_.find(':'));
    if (proxies_.has(protocol)) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxies_[protocol].data());
    } else {
        curl_easy_setopt(curl, CURLOPT_PROXY, nullptr);
    }

    curl_->error[0] = '\0';

    // std::string response_string;
    // std::string header_string;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cpr::util::writeFunction);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string_);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp_header_string_);
}

Response Session::Impl::getResponse(CURLcode curl_error)
{
    auto curl = curl_->handle;
    return getResponse(curl, curl_error);
}

Response Session::Impl::getResponse(CURL* curl, CURLcode curl_error)
{
    char* raw_url;
    long response_code;
    double elapsed;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &raw_url);

    Cookies cookies;
    struct curl_slist* raw_cookies;
    curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &raw_cookies);
    for (struct curl_slist* nc = raw_cookies; nc; nc = nc->next) {
        auto tokens = cpr::util::split(nc->data, '\t');
        auto value = tokens.back();
        tokens.pop_back();
        cookies[tokens.back()] = value;
    }
    curl_slist_free_all(raw_cookies);

    return Response{static_cast<std::int32_t>(response_code),
                    std::move(response_string_),
                    cpr::util::parseHeader(resp_header_string_),
                    std::move(raw_url),
                    elapsed,
                    std::move(cookies),
                    Error(curl_error, curl_->error)};
}

Response Session::Impl::makeRequest(CURL* curl) {
    prepareRequest(curl);
    auto curl_error = curl_easy_perform(curl);

    return getResponse(curl, curl_error);    
}

// clang-format off
Session::Session() : pimpl_{ new Impl{} } {}
Session::~Session() {}
CurlHolder* Session::getHolder() { return pimpl_->getHolder(); }
void Session::prepareRequest() { pimpl_->prepareRequest(); }
Response Session::getResponse(CURLcode curl_error) { return pimpl_->getResponse(curl_error); }
void Session::SetUrl(const Url& url) { pimpl_->SetUrl(url); }
void Session::SetParameters(const Parameters& parameters) { pimpl_->SetParameters(parameters); }
void Session::SetParameters(Parameters&& parameters) { pimpl_->SetParameters(std::move(parameters)); }
void Session::SetHeader(const Header& header) { pimpl_->SetHeader(header); }
void Session::SetTimeout(const Timeout& timeout) { pimpl_->SetTimeout(timeout); }
void Session::SetConnectTimeout(const ConnectTimeout& timeout) { pimpl_->SetConnectTimeout(timeout); }
void Session::SetAuth(const Authentication& auth) { pimpl_->SetAuth(auth); }
void Session::SetDigest(const Digest& auth) { pimpl_->SetDigest(auth); }
void Session::SetUserAgent(const UserAgent& ua) { pimpl_->SetUserAgent(ua); }
void Session::SetPayload(const Payload& payload) { pimpl_->SetPayload(payload); }
void Session::SetPayload(Payload&& payload) { pimpl_->SetPayload(std::move(payload)); }
void Session::SetProxies(const Proxies& proxies) { pimpl_->SetProxies(proxies); }
void Session::SetProxies(Proxies&& proxies) { pimpl_->SetProxies(std::move(proxies)); }
void Session::SetMultipart(const Multipart& multipart) { pimpl_->SetMultipart(multipart); }
void Session::SetMultipart(Multipart&& multipart) { pimpl_->SetMultipart(std::move(multipart)); }
void Session::SetRedirect(const bool& redirect) { pimpl_->SetRedirect(redirect); }
void Session::SetMaxRedirects(const MaxRedirects& max_redirects) { pimpl_->SetMaxRedirects(max_redirects); }
void Session::SetCookies(const Cookies& cookies) { pimpl_->SetCookies(cookies); }
void Session::SetBody(const Body& body) { pimpl_->SetBody(body); }
void Session::SetBody(Body&& body) { pimpl_->SetBody(std::move(body)); }
void Session::SetLowSpeed(const LowSpeed& low_speed) { pimpl_->SetLowSpeed(low_speed); }
void Session::SetVerifySsl(const VerifySsl& verify) { pimpl_->SetVerifySsl(verify); }
void Session::SetOption(const Url& url) { pimpl_->SetUrl(url); }
void Session::SetOption(const Parameters& parameters) { pimpl_->SetParameters(parameters); }
void Session::SetOption(Parameters&& parameters) { pimpl_->SetParameters(std::move(parameters)); }
void Session::SetOption(const Header& header) { pimpl_->SetHeader(header); }
void Session::SetOption(const Timeout& timeout) { pimpl_->SetTimeout(timeout); }
void Session::SetOption(const ConnectTimeout& timeout) { pimpl_->SetConnectTimeout(timeout); }
void Session::SetOption(const Authentication& auth) { pimpl_->SetAuth(auth); }
void Session::SetOption(const Digest& auth) { pimpl_->SetDigest(auth); }
void Session::SetOption(const UserAgent& ua) { pimpl_->SetUserAgent(ua); }
void Session::SetOption(const Payload& payload) { pimpl_->SetPayload(payload); }
void Session::SetOption(Payload&& payload) { pimpl_->SetPayload(std::move(payload)); }
void Session::SetOption(const Proxies& proxies) { pimpl_->SetProxies(proxies); }
void Session::SetOption(Proxies&& proxies) { pimpl_->SetProxies(std::move(proxies)); }
void Session::SetOption(const Multipart& multipart) { pimpl_->SetMultipart(multipart); }
void Session::SetOption(Multipart&& multipart) { pimpl_->SetMultipart(std::move(multipart)); }
void Session::SetOption(const bool& redirect) { pimpl_->SetRedirect(redirect); }
void Session::SetOption(const MaxRedirects& max_redirects) { pimpl_->SetMaxRedirects(max_redirects); }
void Session::SetOption(const Cookies& cookies) { pimpl_->SetCookies(cookies); }
void Session::SetOption(const Body& body) { pimpl_->SetBody(body); }
void Session::SetOption(Body&& body) { pimpl_->SetBody(std::move(body)); }
void Session::SetOption(const LowSpeed& low_speed) { pimpl_->SetLowSpeed(low_speed); }
void Session::SetOption(const VerifySsl& verify) { pimpl_->SetVerifySsl(verify); }
void Session::SetOption(const Verbose& verbose) { pimpl_->SetVerbose(verbose); }
Response Session::Delete(bool do_request) { return pimpl_->Delete(do_request); }
Response Session::Get(bool do_request) { return pimpl_->Get(do_request); }
Response Session::Head(bool do_request) { return pimpl_->Head(do_request); }
Response Session::Options(bool do_request) { return pimpl_->Options(do_request); }
Response Session::Patch(bool do_request) { return pimpl_->Patch(do_request); }
Response Session::Post(bool do_request) { return pimpl_->Post(do_request); }
Response Session::Put(bool do_request) { return pimpl_->Put(do_request); }
// clang-format on


MultiSession::MultiSession()
: current_session_(NULL)
{
    multiCurl_ = curl_multi_init();
}

MultiSession::~MultiSession()
{
    for(auto ms : map_session_)
    {
        Session* s = ms.second;
        if(s != NULL)
        {
            curl_multi_remove_handle(multiCurl_, s->getHolder()->handle);
        }
        delete s;
    }

    map_session_.clear();

	curl_multi_cleanup(multiCurl_);
}

std::list<Response> MultiSession::doReuests()
{
    for(auto s : map_session_)
    {
        s.second->prepareRequest();
        curl_multi_add_handle(multiCurl_, s.second->getHolder()->handle);
    }

    int running_handlers = 0;
    do {
        curl_multi_wait(multiCurl_, nullptr, 0, 2000, nullptr);  //timeout 2000ms
        curl_multi_perform(multiCurl_, &running_handlers);
    } while (running_handlers > 0);

	int         msgs_left;  
    CURLMsg *   msg;
    std::list<Response> list_resp;
    while((msg = curl_multi_info_read(multiCurl_, &msgs_left)))  
    {  
        if (CURLMSG_DONE == msg->msg)  
        {
            list_resp.emplace_back(map_session_[msg->easy_handle]->getResponse(msg->data.result));
        }
    }

    return list_resp;
}

void MultiSession::SetOption(const NEW_OPTION& new_option)
{
    if(new_option.is_new_option) 
    {
        Session* s = new Session();
        switch(new_option.option_type)
        {
        case OPTION_TYPE::DEL:
            s->Delete(false);
            break;
        case OPTION_TYPE::GET:
            s->Get(false);
            break;
        case OPTION_TYPE::HEAD:
            s->Head(false);
            break;
        case OPTION_TYPE::OPTIONS:
            s->Options(false);
            break;
        case OPTION_TYPE::PATCH:
            s->Patch(false);
            break;
        case OPTION_TYPE::POST:
            s->Post(false);
            break;
        case OPTION_TYPE::PUT:
            s->Put(false);
            break;
        default:
            std::cout << "err option, not supported yet" << std::endl;
            delete s;
            break;
        }

        map_session_.emplace(s->getHolder()->handle, s);
        current_session_ = s;
    }
}

void MultiSession::SetOption(const Url& url) { if(current_session_) current_session_->SetUrl(url); }
void MultiSession::SetOption(const Parameters& parameters) { if(current_session_) current_session_->SetParameters(parameters); }
void MultiSession::SetOption(Parameters&& parameters) { if(current_session_) current_session_->SetParameters(std::move(parameters)); }
void MultiSession::SetOption(const Header& header) { if(current_session_) current_session_->SetHeader(header); }
void MultiSession::SetOption(const Timeout& timeout) { if(current_session_) current_session_->SetTimeout(timeout); }
void MultiSession::SetOption(const ConnectTimeout& timeout) { if(current_session_) current_session_->SetConnectTimeout(timeout); }
void MultiSession::SetOption(const Authentication& auth) { if(current_session_) current_session_->SetAuth(auth); }
void MultiSession::SetOption(const Digest& auth) { if(current_session_) current_session_->SetDigest(auth); }
void MultiSession::SetOption(const UserAgent& ua) { if(current_session_) current_session_->SetUserAgent(ua); }
void MultiSession::SetOption(const Payload& payload) { if(current_session_) current_session_->SetPayload(payload); }
void MultiSession::SetOption(Payload&& payload) { if(current_session_) current_session_->SetPayload(std::move(payload)); }
void MultiSession::SetOption(const Proxies& proxies) { if(current_session_) current_session_->SetProxies(proxies); }
void MultiSession::SetOption(Proxies&& proxies) { if(current_session_) current_session_->SetProxies(std::move(proxies)); }
void MultiSession::SetOption(const Multipart& multipart) { if(current_session_) current_session_->SetMultipart(multipart); }
void MultiSession::SetOption(Multipart&& multipart) { if(current_session_) current_session_->SetMultipart(std::move(multipart)); }
void MultiSession::SetOption(const bool& redirect) { if(current_session_) current_session_->SetRedirect(redirect); }
void MultiSession::SetOption(const MaxRedirects& max_redirects) { if(current_session_) current_session_->SetMaxRedirects(max_redirects); }
void MultiSession::SetOption(const Cookies& cookies) { if(current_session_) current_session_->SetCookies(cookies); }
void MultiSession::SetOption(const Body& body) { if(current_session_) current_session_->SetBody(body); }
void MultiSession::SetOption(Body&& body) { if(current_session_) current_session_->SetBody(std::move(body)); }
void MultiSession::SetOption(const LowSpeed& low_speed) { if(current_session_) current_session_->SetLowSpeed(low_speed); }
void MultiSession::SetOption(const VerifySsl& verify) { if(current_session_) current_session_->SetVerifySsl(verify); }
void MultiSession::SetOption(const Verbose& verbose) { if(current_session_) current_session_->SetOption(verbose); }

} // namespace cpr
