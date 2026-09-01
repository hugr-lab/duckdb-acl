//===----------------------------------------------------------------------===//
// acl_quack_embed.cpp — registration for the embedded quack door (spec 063)
//
// The acl_quack_* server settings the embedded (renamed) graph reads, and the
// acl_quack_scan_data drain table function the server INSERTs through. Auth/authz
// (acl_quack_authenticate / acl_quack_authorize) are scalar functions registered
// by acl_admin_functions.cpp; the two settings below simply default to them, so a
// plain acl_quack_serve needs no SET. Everything is acl_quack_*-named, so a
// standalone quack loaded alongside registers its own quack_* names without clash.
//===----------------------------------------------------------------------===//

#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/config.hpp"

#include "acl_quack_embed.hpp"

#include "quack_scan_from_client.hpp"
#include "quack_rebalancer_sink.hpp"

namespace duckdb {
namespace acl {

void RegisterAclQuackEmbed(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());

	// The two callback names the embedded server resolves per request; default straight to acl's own
	// scalars so acl_quack_serve needs no wiring. GLOBAL, like every server-wide knob.
	config.AddExtensionOption("acl_quack_authentication_function",
	                          "acl embedded door: authentication callback the server SELECTs per connection",
	                          LogicalType::VARCHAR, Value("acl_quack_authenticate"), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_quack_authorization_function",
	                          "acl embedded door: authorization callback the server SELECTs per statement",
	                          LogicalType::VARCHAR, Value("acl_quack_authorize"), nullptr, SetScope::GLOBAL);

	// Server tunables (mirrors quack's own defaults; values from quack_rebalancer_sink.hpp so a bump
	// carries them along). Non-GLOBAL where quack left them session-scoped.
	config.AddExtensionOption("acl_quack_server_max_connections",
	                          "acl embedded door: max concurrent connections the server accepts", LogicalType::UBIGINT,
	                          Value::UBIGINT(1024), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_quack_server_keep_alive_timeout",
	                          "acl embedded door: seconds an idle keep-alive connection is kept open",
	                          LogicalType::UBIGINT, Value::UBIGINT(300), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_quack_prepare_inline_rows",
	                          "acl embedded door: rows returned inline in a PREPARE response before FETCH",
	                          LogicalType::UBIGINT, Value::UBIGINT(QUACK_PREPARE_INLINE_ROWS_DEFAULT));
	config.AddExtensionOption("acl_quack_debug_emit_delay_ms",
	                          "acl embedded door: DEBUG max random ms delay before the collector publishes a batch",
	                          LogicalType::UBIGINT, Value::UBIGINT(0));
	config.AddExtensionOption("acl_quack_target_batch_bytes",
	                          "acl embedded door: target in-memory size of one rebalanced wire batch",
	                          LogicalType::UBIGINT, Value::UBIGINT(QUACK_TARGET_BATCH_BYTES_DEFAULT));
	config.AddExtensionOption("acl_quack_rebalance_buffer_bytes",
	                          "acl embedded door: pending bytes the rebalancer buffers before gating producers",
	                          LogicalType::UBIGINT, Value::UBIGINT(QUACK_REBALANCE_BUFFER_BYTES_DEFAULT));
	config.AddExtensionOption("acl_quack_fetch_producer_buffer_bytes",
	                          "acl embedded door: server-side cap on bytes the fetch collector buffers ahead",
	                          LogicalType::UBIGINT, Value::UBIGINT(QUACK_FETCH_PRODUCER_BUFFER_BYTES_DEFAULT));
	config.AddExtensionOption("acl_quack_enable_reconnects",
	                          "acl embedded door: cache the last result until acknowledged (reconnect support)",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(false));
	config.AddExtensionOption("acl_quack_cache_max_rows",
	                          "acl embedded door: max rows the server retains in the result cache (0 = unlimited)",
	                          LogicalType::UBIGINT, Value::UBIGINT(100000), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_quack_result_ttl",
	                          "acl embedded door: seconds an idle cached result is kept (0 = never)",
	                          LogicalType::UBIGINT, Value::UBIGINT(3600), nullptr, SetScope::GLOBAL);

	// The drain: the server runs INSERT ... SELECT * FROM acl_quack_scan_data('<stream>'). Internal;
	// principals are barred from calling it directly by the function gate (denylist, acl_policy.cpp).
	loader.RegisterFunction(QuackScanFromClientFunction::GetFunction());
}

} // namespace acl
} // namespace duckdb
