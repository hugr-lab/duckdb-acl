// Spec 135: the session-state cookie's codec. Pure: a state in, a cookie value out, and back - bounded both
// ways, and an input that is not exactly what this build writes reads as UNREADABLE, never partly.

#include "acl_session_state.hpp"

#include "yyjson.hpp"

#include <cctype>
#include <cstdio>

namespace duckdb {
namespace acl {
namespace {

using duckdb_yyjson::yyjson_doc;
using duckdb_yyjson::yyjson_val;

constexpr const char *B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string Base64UrlEncode(const std::string &in) {
	std::string out;
	out.reserve((in.size() + 2) / 3 * 4);
	std::size_t i = 0;
	for (; i + 2 < in.size(); i += 3) {
		unsigned n = (unsigned char)in[i] << 16 | (unsigned char)in[i + 1] << 8 | (unsigned char)in[i + 2];
		out += B64URL[n >> 18 & 63];
		out += B64URL[n >> 12 & 63];
		out += B64URL[n >> 6 & 63];
		out += B64URL[n & 63];
	}
	if (i + 1 == in.size()) {
		unsigned n = (unsigned char)in[i] << 16;
		out += B64URL[n >> 18 & 63];
		out += B64URL[n >> 12 & 63];
	} else if (i + 2 == in.size()) {
		unsigned n = (unsigned char)in[i] << 16 | (unsigned char)in[i + 1] << 8;
		out += B64URL[n >> 18 & 63];
		out += B64URL[n >> 12 & 63];
		out += B64URL[n >> 6 & 63];
	}
	return out;
}

int B64Value(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '-') {
		return 62;
	}
	if (c == '_') {
		return 63;
	}
	return -1;
}

//! strict: the alphabet only, no padding, no length that base64 cannot end on
bool Base64UrlDecode(const std::string &in, std::string &out) {
	if (in.size() % 4 == 1) {
		return false;
	}
	out.clear();
	unsigned buffer = 0;
	int bits = 0;
	for (char c : in) {
		int v = B64Value(c);
		if (v < 0) {
			return false;
		}
		buffer = buffer << 6 | (unsigned)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out += (char)(buffer >> bits & 0xFF);
		}
	}
	// the bits left over must be zero: one value, one spelling
	return (buffer & ((1u << bits) - 1)) == 0;
}

std::string Quote(const std::string &value) {
	std::string out = "\"";
	for (unsigned char c : value) {
		switch (c) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		default:
			if (c < 0x20) {
				char escaped[8];
				snprintf(escaped, sizeof(escaped), "\\u%04x", c);
				out += escaped;
			} else {
				out += (char)c;
			}
		}
	}
	return out + "\"";
}

std::string Json(const SessionState &state) {
	std::string out = "{\"v\":1,\"p\":" + Quote(state.principal);
	if (!state.use_catalog.empty() || !state.use_schema.empty()) {
		out += ",\"use\":{\"catalog\":" + Quote(state.use_catalog) + ",\"schema\":" + Quote(state.use_schema) + "}";
	}
	if (!state.settings.empty()) {
		out += ",\"set\":{";
		bool first = true;
		for (auto &setting : state.settings) {
			out += (first ? "" : ",") + Quote(setting.first) + ":" + Quote(setting.second);
			first = false;
		}
		out += "}";
	}
	if (!state.pinned.empty()) {
		out += ",\"pinned\":[";
		for (std::size_t i = 0; i < state.pinned.size(); i++) {
			out += (i ? "," : "") + Quote(state.pinned[i]);
		}
		out += "]";
	}
	return out + "}";
}

struct Doc {
	explicit Doc(const std::string &text) : doc(duckdb_yyjson::yyjson_read(text.c_str(), text.size(), 0)) {
	}
	~Doc() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}
	Doc(const Doc &) = delete;
	Doc &operator=(const Doc &) = delete;
	yyjson_doc *doc;
};

bool IsKnownPin(const std::string &pin) {
	return pin == "transaction" || pin == "temp" || pin == "view_as" || pin == "context";
}

//! a JSON string whole: its length, not its first NUL - a NUL anywhere is a value this build never writes
bool Text(yyjson_val *val, std::string &out) {
	if (!duckdb_yyjson::yyjson_is_str(val)) {
		return false;
	}
	out.assign(duckdb_yyjson::yyjson_get_str(val), duckdb_yyjson::yyjson_get_len(val));
	return out.find('\0') == std::string::npos;
}

bool CaseEquals(const std::string &a, const char *b) {
	std::size_t i = 0;
	for (; i < a.size() && b[i]; i++) {
		if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) {
			return false;
		}
	}
	return i == a.size() && !b[i];
}

} // namespace

const char *PortableSetting(const std::string &name) {
	for (auto setting : PORTABLE_SETTINGS) {
		if (CaseEquals(name, setting)) {
			return setting;
		}
	}
	return nullptr;
}

std::string EncodeSessionState(const SessionState &state) {
	if (state.Empty()) {
		return std::string();
	}
	auto encoded = Base64UrlEncode(Json(state));
	if (encoded.size() > SESSION_STATE_MAX_BYTES) {
		// the pins are what a move must not lose silently: they stay, and the context they cannot carry is one more
		SessionState bounded;
		bounded.principal = state.principal;
		bounded.pinned = state.pinned;
		bounded.pinned.emplace_back("context");
		return Base64UrlEncode(Json(bounded));
	}
	return encoded;
}

SessionStateRead DecodeSessionState(const std::string &value, SessionState &out) {
	out = SessionState();
	if (value.empty()) {
		return SessionStateRead::ABSENT;
	}
	std::string text;
	if (value.size() > SESSION_STATE_MAX_INPUT || !Base64UrlDecode(value, text)) {
		return SessionStateRead::UNREADABLE;
	}
	Doc json(text);
	auto *root = json.doc ? duckdb_yyjson::yyjson_doc_get_root(json.doc) : nullptr;
	if (!root || !duckdb_yyjson::yyjson_is_obj(root)) {
		return SessionStateRead::UNREADABLE;
	}
	SessionState read;
	bool versioned = false;
	bool owned = false;
	duckdb_yyjson::yyjson_obj_iter iter;
	duckdb_yyjson::yyjson_obj_iter_init(root, &iter);
	while (auto *key = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
		std::string name = duckdb_yyjson::yyjson_get_str(key);
		auto *val = duckdb_yyjson::yyjson_obj_iter_get_val(key);
		if (name == "v") {
			if (!duckdb_yyjson::yyjson_is_int(val) || duckdb_yyjson::yyjson_get_int(val) != 1) {
				return SessionStateRead::UNREADABLE;
			}
			versioned = true;
		} else if (name == "p") {
			if (!Text(val, read.principal) || read.principal.empty()) {
				return SessionStateRead::UNREADABLE;
			}
			owned = true;
		} else if (name == "use") {
			if (!duckdb_yyjson::yyjson_is_obj(val)) {
				return SessionStateRead::UNREADABLE;
			}
			duckdb_yyjson::yyjson_obj_iter use;
			duckdb_yyjson::yyjson_obj_iter_init(val, &use);
			while (auto *part = duckdb_yyjson::yyjson_obj_iter_next(&use)) {
				std::string part_name, text_val;
				if (!Text(part, part_name) || !Text(duckdb_yyjson::yyjson_obj_iter_get_val(part), text_val)) {
					return SessionStateRead::UNREADABLE;
				}
				if (part_name == "catalog") {
					read.use_catalog = text_val;
				} else if (part_name == "schema") {
					read.use_schema = text_val;
				} else {
					return SessionStateRead::UNREADABLE;
				}
			}
		} else if (name == "set") {
			if (!duckdb_yyjson::yyjson_is_obj(val)) {
				return SessionStateRead::UNREADABLE;
			}
			duckdb_yyjson::yyjson_obj_iter set;
			duckdb_yyjson::yyjson_obj_iter_init(val, &set);
			while (auto *setting = duckdb_yyjson::yyjson_obj_iter_next(&set)) {
				std::string setting_name, setting_val;
				if (!Text(setting, setting_name) ||
				    !Text(duckdb_yyjson::yyjson_obj_iter_get_val(setting), setting_val)) {
					return SessionStateRead::UNREADABLE;
				}
				// only the list's settings, each once: a restore runs a statement per item, so the items are bounded
				auto known = PortableSetting(setting_name);
				if (!known) {
					return SessionStateRead::UNREADABLE;
				}
				for (auto &seen : read.settings) {
					if (seen.first == known) {
						return SessionStateRead::UNREADABLE;
					}
				}
				read.settings.emplace_back(known, setting_val);
			}
		} else if (name == "pinned") {
			if (!duckdb_yyjson::yyjson_is_arr(val)) {
				return SessionStateRead::UNREADABLE;
			}
			duckdb_yyjson::yyjson_arr_iter pins;
			duckdb_yyjson::yyjson_arr_iter_init(val, &pins);
			while (auto *pin = duckdb_yyjson::yyjson_arr_iter_next(&pins)) {
				std::string pin_name;
				if (!Text(pin, pin_name)) {
					return SessionStateRead::UNREADABLE;
				}
				// a reason this build does not know still pins: the session held something it cannot carry
				read.pinned.push_back(IsKnownPin(pin_name) ? pin_name : "context");
			}
		} else {
			return SessionStateRead::UNREADABLE;
		}
	}
	if (!versioned || !owned) {
		return SessionStateRead::UNREADABLE;
	}
	out = std::move(read);
	return SessionStateRead::OK;
}

std::string SessionStateSetCookie(const std::string &encoded) {
	if (encoded.empty()) {
		return std::string(SESSION_STATE_COOKIE) + "=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict";
	}
	return std::string(SESSION_STATE_COOKIE) + "=" + encoded + "; HttpOnly; Path=/; SameSite=Strict";
}

std::string SessionStateLost(const std::vector<std::string> &pinned) {
	std::string out;
	auto add = [&](const char *what) {
		if (out.find(what) == std::string::npos) {
			out += (out.empty() ? "" : ", ") + std::string(what);
		}
	};
	for (auto &pin : pinned) {
		if (pin == "transaction") {
			add("its open transaction");
		} else if (pin == "temp") {
			add("its temp tables");
		} else if (pin == "view_as") {
			add("its view-as mode");
		} else {
			add("its session context");
		}
	}
	return out.empty() ? "its session context" : out;
}

} // namespace acl
} // namespace duckdb
