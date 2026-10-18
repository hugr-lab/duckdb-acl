// The node's label in its sessions' names (spec 134). Behind a front that keeps no table of sessions,
// the node names them: both doors set one cookie, `acl_node=<label>`, and the quack door's connection
// ids start with `<label>.`. The label is a routing hint for whoever sits in front - never an
// authority here: an incoming value is only compared with the node's own. Header-only and pure, so
// every rule is checked in test/cpp/test_acl_node_label.cpp without an instance.

#pragma once

#include <string>
#include <vector>

namespace duckdb {
namespace acl {

//! The one cookie both doors set while the node has a label.
constexpr const char *NODE_LABEL_COOKIE = "acl_node";

//! A DNS-1123 label: 1..63 of [a-z0-9-], a letter or a digit at both ends - so it never holds the `.`
//! that ends it in a connection id, nor a byte a cookie or a header would have to escape.
inline bool ValidNodeLabel(const std::string &label) {
	if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
		return false;
	}
	for (char c : label) {
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
			return false;
		}
	}
	return true;
}

//! The value of the cookie `name` in one Cookie header (`a=1; b=2`), parsed by NAME - never a
//! substring of another cookie's value. False when the header carries no such cookie.
inline bool CookieNamed(const std::string &header, const char *name, std::string &value) {
	auto trim = [](const std::string &text) {
		auto begin = text.find_first_not_of(" \t");
		auto end = text.find_last_not_of(" \t");
		return begin == std::string::npos ? std::string() : text.substr(begin, end - begin + 1);
	};
	size_t pos = 0;
	while (pos <= header.size()) {
		auto semi = header.find(';', pos);
		auto piece = header.substr(pos, semi == std::string::npos ? std::string::npos : semi - pos);
		auto eq = piece.find('=');
		if (eq != std::string::npos && trim(piece.substr(0, eq)) == name) {
			value = trim(piece.substr(eq + 1));
			return true;
		}
		if (semi == std::string::npos) {
			break;
		}
		pos = semi + 1;
	}
	return false;
}

//! The Set-Cookie value the label asks for: `acl_node=<label>; HttpOnly; Path=/; SameSite=Strict`
//! when the label is set and none of the request's Cookie headers carries `acl_node=<label>` already
//! (a new client, one re-seated from another node, a label changed); empty otherwise.
inline std::string NodeLabelSetCookie(const std::string &label, const std::vector<std::string> &cookie_headers) {
	if (label.empty()) {
		return std::string();
	}
	for (auto &header : cookie_headers) {
		std::string carried;
		if (CookieNamed(header, NODE_LABEL_COOKIE, carried) && carried == label) {
			return std::string();
		}
	}
	return std::string(NODE_LABEL_COOKIE) + "=" + label + "; HttpOnly; Path=/; SameSite=Strict";
}

//! What a quack connection id starts with: `<label>.`, or nothing without a label. The id's random
//! part follows unchanged - the label is public, the rest is the connection's secret.
inline std::string NodeLabelIdPrefix(const std::string &label) {
	return label.empty() ? std::string() : label + ".";
}

} // namespace acl
} // namespace duckdb
