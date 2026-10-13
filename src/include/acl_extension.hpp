#pragma once

#include "duckdb.hpp"

namespace duckdb {
namespace acl {
struct PolicyStore; // a struct: MSVC mangles the kind it first sees
}

//! spec 127: acl's whole load - settings, the parser override, the doors, every acl_* function - answering the
//! store, for an extension that builds acl into itself (hugr_node) and then registers its own part on it
shared_ptr<acl::PolicyStore> LoadAclCore(ExtensionLoader &loader);

class AclExtension : public Extension {
public:
	void Load(ExtensionLoader &loader) override;
	std::string Name() override;
	std::string Version() const override;
};

} // namespace duckdb
