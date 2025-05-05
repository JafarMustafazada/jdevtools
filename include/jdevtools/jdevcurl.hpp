#ifndef JDEVTOOLS_JDEVCURL_HPP
#define JDEVTOOLS_JDEVCURL_HPP

#include <stdexcept>
#include <string>
#include <vector>

namespace {
#if defined(_WIN32)
#define popen _popen
#define pclose _pclose
#endif

	inline std::string exec(const char *cmd) {
		char buffer[128];
		std::string result = "";
		FILE *pipe = popen(cmd, "r");
		if (!pipe) throw std::runtime_error("popen() failed!");
		try {
			while (fgets(buffer, sizeof buffer, pipe) != NULL) {
				result += buffer;
			}
		} catch (...) {
			pclose(pipe);
			throw;
		}
		pclose(pipe);
		return result;
	}
}

namespace jdevtools {
	struct requestData {
		std::string url = "example.com";
		std::vector<std::string> headers;
		// url encoded data
		std::string postData = "";
		// data to be url encoded
		std::vector<std::string> urlEncodeDatas;
	};

	// runs commad with following startings:
	// always `curl -s -o - `
	// + if post `-X POST "url"`
	// + if nopost `--location "url"`
	// + for each header ` -H "header"`
	// + for each data to be url encoded ` --data-urlencode "urlEncodeData"`
	// + for post data ` -d "postData"`
	inline std::string sender(const requestData &req, bool isPost = false) {
		std::string command = "curl -s -o - ";
		if (isPost) command += "-X POST \"" + req.url + '"';
		else command += "--location \"" + req.url + '"';
		for (int i = 0; i < req.headers.size(); i++) {
			command += " -H \"" + req.headers[i] + '"';
		}
		if (req.postData.size()) command += " -d \"" + req.postData + '"';
		for (int i = 0; i < req.urlEncodeDatas.size(); i++) {
			command += " --data-urlencode \"" + req.urlEncodeDatas[i] + '"';
		}
		return exec(command.data());
	}

	// runs commad with following starting:
	//`curl -s -o - `
	inline std::string sender(const char *cmd) {
		std::string command = "curl -s -o - " + std::string(cmd);
		return exec(command.data());
	}
}

#endif