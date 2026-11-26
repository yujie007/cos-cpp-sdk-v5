#include "util/http_sender.h"
#include "cos_api.h"
#include <windows.h>
#include <iostream>
#include <sstream>

static std::string utf8(const wchar_t* value) {
  const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
  std::string result(size, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], size, NULL, NULL);
  result.pop_back();
  return result;
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 5) return 2;
  const int branch = _wtoi(argv[1]);
  const std::string url = utf8(argv[2]);
  const std::string ca = utf8(argv[3]);
  const std::string payload = "cos-ca-utf8-upload-probe";
  if (branch == 2) {
    qcloud_cos::CosConfig config(125, "test-id", "test-key", "ap-beijing");
    config.SetDestDomain(url.substr(8, url.find('/', 8) - 8));
    config.SetDomainSameToHost(true);
    qcloud_cos::CosAPI client(config);
    qcloud_cos::PutObjectByFileReq request("test-125", "upload", utf8(argv[4]));
    request.SetWideCharPath();
    request.SetHttps();
    request.SetCaLocation(ca);
    request.SetConnTimeoutInms(3000);
    request.SetRecvTimeoutInms(3000);
    qcloud_cos::PutObjectByFileResp response;
    const auto result = client.PutObject(request, &response);
    std::cout << "PUT success=" << result.IsSucc() << " status=" << result.GetHttpStatus() << " error=" << result.GetErrorMsg() << std::endl;
    return result.IsSucc() ? 0 : 1;
  }
  std::map<std::string, std::string> headers, response_headers;
  std::ostringstream response;
  std::string error, xml_error;
  int status;
  if (branch == 0) {
    std::istringstream input(payload);
    status = qcloud_cos::HttpSender::SendRequest(qcloud_cos::SharedTransferHandler(), "PUT", url, {}, headers, input, 3000, 3000, &response_headers, response, &error, false, true, ca);
  } else {
    uint64_t bytes = 0;
    status = qcloud_cos::HttpSender::SendRequest(qcloud_cos::SharedTransferHandler(), "PUT", url, {}, headers, payload, 3000, 3000, &response_headers, &xml_error, response, &error, &bytes, false, true, ca);
  }
  std::cout << "branch=" << branch << " status=" << status << " error=" << error << std::endl;
  return status == 200 && response.str() == "ACK" ? 0 : 1;
}
