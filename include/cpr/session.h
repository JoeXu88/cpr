#ifndef CPR_SESSION_H
#define CPR_SESSION_H

#include <cstdint>
#include <memory>
#include <map>
#include <list>
#include <curl/curl.h>

#include "cpr/auth.h"
#include "cpr/body.h"
#include "cpr/cookies.h"
#include "cpr/cprtypes.h"
#include "cpr/digest.h"
#include "cpr/low_speed.h"
#include "cpr/max_redirects.h"
#include "cpr/multipart.h"
#include "cpr/parameters.h"
#include "cpr/payload.h"
#include "cpr/proxies.h"
#include "cpr/response.h"
#include "cpr/timeout.h"
#include "cpr/connect_timeout.h"
#include "cpr/low_speed.h"
#include "cpr/ssl_options.h"
#include "cpr/timeout.h"
#include "cpr/user_agent.h"
#include "cpr/session.h"
#include "cpr/verbose.h"
#include "cpr/curlholder.h"

namespace cpr {

enum class OPTION_TYPE {
  GET = 0,
  DEL,
  HEAD,
  OPTIONS,
  PATCH,
  POST,
  PUT
};

struct NEW_OPTION {
  bool is_new_option{true};
  OPTION_TYPE option_type;

  NEW_OPTION(const OPTION_TYPE& option):option_type(option) {}
};

class Session {
  public:
    Session();
    ~Session();

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
    void SetVerifySsl(const VerifySsl& verify);

    // Used in templated functions
    void SetOption(const Url& url);
    void SetOption(const Parameters& parameters);
    void SetOption(Parameters&& parameters);
    void SetOption(const Header& header);
    void SetOption(const Timeout& timeout);
    void SetOption(const ConnectTimeout& timeout);
    void SetOption(const Authentication& auth);
    void SetOption(const Digest& auth);
    void SetOption(const UserAgent& ua);
    void SetOption(Payload&& payload);
    void SetOption(const Payload& payload);
    void SetOption(Proxies&& proxies);
    void SetOption(const Proxies& proxies);
    void SetOption(Multipart&& multipart);
    void SetOption(const Multipart& multipart);
    void SetOption(const bool& redirect);
    void SetOption(const MaxRedirects& max_redirects);
    void SetOption(const Cookies& cookies);
    void SetOption(Body&& body);
    void SetOption(const Body& body);
    void SetOption(const LowSpeed& low_speed);
    void SetOption(const VerifySsl& verify);
    void SetOption(const Verbose& verbose);

    void prepareRequest();
    Response getResponse(CURLcode curl_error);

    Response Delete(bool do_request = true);
    Response Get(bool do_request = true);
    Response Head(bool do_request = true);
    Response Options(bool do_request = true);
    Response Patch(bool do_request = true);
    Response Post(bool do_request = true);
    Response Put(bool do_request = true);

  private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

class MultiSession {
  public:
    MultiSession();
    ~MultiSession();

    // Used in templated functions
    void SetOption(const Url& url);
    void SetOption(const Parameters& parameters);
    void SetOption(Parameters&& parameters);
    void SetOption(const Header& header);
    void SetOption(const Timeout& timeout);
    void SetOption(const ConnectTimeout& timeout);
    void SetOption(const Authentication& auth);
    void SetOption(const Digest& auth);
    void SetOption(const UserAgent& ua);
    void SetOption(Payload&& payload);
    void SetOption(const Payload& payload);
    void SetOption(Proxies&& proxies);
    void SetOption(const Proxies& proxies);
    void SetOption(Multipart&& multipart);
    void SetOption(const Multipart& multipart);
    void SetOption(const bool& redirect);
    void SetOption(const MaxRedirects& max_redirects);
    void SetOption(const Cookies& cookies);
    void SetOption(Body&& body);
    void SetOption(const Body& body);
    void SetOption(const LowSpeed& low_speed);
    void SetOption(const VerifySsl& verify);
    void SetOption(const Verbose& verbose);
    void SetOption(const NEW_OPTION& new_option); //for split session option

    std::list<Response> doReuests();

  private:
    std::map<CURL*, Session*> map_session_;
    Session* current_session_;
    CURLM* multiCurl_;
};

} // namespace cpr

#endif
