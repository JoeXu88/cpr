#include <cstdio>
#include <fstream>
#include <string>
#include <iostream>
#include <map>

#include <cpr/cpr.h>
#include <cpr/multipart.h>

void dumpRespon(const cpr::Response& response)
{
    std::cout << "resp from url: " << response.url << std::endl;
    std::cout << "errCode:" << (int)response.error.code << "; msg:" << response.error.message << std::endl;
    std::cout << "status code:" << response.status_code << std::endl;
    std::cout << "resonse:" << response.text << std::endl;
}

int main()
{
    std::string url1 = "http://www.baidu.com/";
    std::string url2 = "http://coolshell.cn";

    // while(true)
    {
    auto response = cpr::Get(url2);
    dumpRespon(response);

    auto list_resp = cpr::MultiRequest(cpr::NEW_OPTION(cpr::OPTION_TYPE::GET), cpr::Url(url1),
                                        cpr::NEW_OPTION(cpr::OPTION_TYPE::HEAD), cpr::Url(url2));

    for(auto resp : list_resp)
    {
        dumpRespon(resp);
    }
    }

    return 0;
}

