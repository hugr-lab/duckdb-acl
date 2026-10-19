// Placement (spec 096): which sessions a node of a resource group serves. Header-only and pure - the
// store hands in the node's group, whether the catalog knows it, and the principal's groups (bound,
// or the default group's for a principal bound to none) - so every row of the decision is simulated
// in test/cpp/test_acl_placement.cpp.

#pragma once

#include <string>
#include <vector>

namespace duckdb {
namespace acl {

struct PlacementDecision {
	bool admitted = true;
	//! the one group whose limits apply ('' = the 085 merge over every group of the principal)
	std::string group;
	//! why a refused session is refused - safe to tell the client and the front: group names only
	std::string refusal;
};

//! `node_group` '' = the node serves everyone (the single-node installation, and every node before
//! 096). `principal_groups` are the groups that serve the principal: its roles' groups, or the default
//! group when its roles are in none (empty when neither).
inline PlacementDecision Place(const std::string &node_group, bool node_group_known,
                               const std::vector<std::string> &principal_groups) {
	PlacementDecision out;
	if (node_group.empty()) {
		return out;
	}
	if (!node_group_known) {
		out.admitted = false;
		out.refusal = "acl: this node's resource group \"" + node_group +
		              "\" is not a resource group of the policy - it serves no new session until it is";
		return out;
	}
	for (auto &group : principal_groups) {
		if (group == node_group) {
			out.group = group;
			return out;
		}
	}
	out.admitted = false;
	if (principal_groups.empty()) {
		out.refusal = "acl: this node serves resource group \"" + node_group +
		              "\" - no resource group serves your roles (and there is no default group)";
	} else {
		std::string served;
		for (auto &group : principal_groups) {
			served += (served.empty() ? "\"" : ", \"") + group + "\"";
		}
		out.refusal =
		    "acl: this node serves resource group \"" + node_group + "\" - your roles are served by " + served;
	}
	return out;
}

//! The groups that serve a principal, for a front (spec 096 addendum): Flight's trailer and quack's CONNECT header
//! `x-acl-resource-groups`. Each name percent-encoded (everything but RFC 3986's unreserved characters), joined by
//! commas - ASCII whatever a group is called, and a comma never inside a name. It tells nobody more than the refusal's
//! sentence does.
constexpr const char *RESOURCE_GROUPS_HEADER = "x-acl-resource-groups";

inline std::string ResourceGroupsHeader(const std::vector<std::string> &groups) {
	static const char *HEX = "0123456789ABCDEF";
	std::string out;
	for (auto &group : groups) {
		if (!out.empty()) {
			out += ',';
		}
		for (unsigned char c : group) {
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
			    c == '_' || c == '~') {
				out += static_cast<char>(c);
			} else {
				out += '%';
				out += HEX[c >> 4];
				out += HEX[c & 15];
			}
		}
	}
	return out;
}

} // namespace acl
} // namespace duckdb
