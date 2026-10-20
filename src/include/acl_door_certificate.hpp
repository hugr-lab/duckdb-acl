//===----------------------------------------------------------------------===//
//                         DuckDB ACL
//
// acl_door_certificate.hpp
//
// Spec 140: a door picks up a renewed certificate. A door served from LOCAL files (cert-manager's
// csi-driver renews them in place) re-reads them on an interval: a pair that parses and whose key
// matches its certificate is handed to the door's swap, anything else is refused and reported - the
// last good pair keeps serving. The status (the served certificate's notAfter, when it was taken,
// the last refusal's class) is what the load report shows. The watcher is compiled in the flight
// build only (its OpenSSL); this header names no OpenSSL type.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace duckdb {
namespace acl {

//! What a served door's certificate is, as its watcher last saw it (the load report's `certificates`).
struct DoorCertificateStatus {
	//! "flight" or "quack"
	string door;
	//! the door is served from local files and re-reads them (spec 140); false: read once
	bool watched = false;
	//! the served certificate's notAfter, ISO 8601 UTC ("" when it could not be read)
	string not_after;
	//! when the served pair was taken, unix seconds
	int64_t refreshed_at = 0;
	//! the class of the last refused renewal ("" when the files hold the served pair): unreadable,
	//! certificate_unparsable, key_unparsable, key_mismatch, refused_by_door; on an unwatched door served from
	//! local files, anchor_unavailable: the Flight door could not watch them (spec 140) and read its pair once
	string error;
};

//! Whether a certificate / key argument names a local file the door can watch: not inline PEM, and no
//! scheme but file:// (a location duckdb's filesystem reads remotely is read once, as before).
bool IsLocalCertificatePath(const string &arg);
//! The path a local argument names (file:// cut). Both helpers are acl_door_common's (every build).
string LocalCertificatePath(const string &arg);

//! Parse a PEM pair: the first certificate, the private key, and whether the key is the certificate's.
//! On success `not_after` is the certificate's notAfter (ISO 8601 UTC); on failure `error_class` is one
//! of the DoorCertificateStatus::error classes. Never logs or returns PEM text.
bool CheckCertificatePair(const string &cert_pem, const string &key_pem, string &not_after, string &error_class);

//! Re-reads a door's certificate and key from local files every `interval_seconds`. A changed pair that
//! checks is handed to `apply` (nullptr: the door swaps by itself - Flight's gRPC file watcher - and
//! this only reports); `report` gets every status change, `failed` set when a renewal was refused. The
//! flight build's only (acl_door_certificate.cpp, its OpenSSL), as is CheckCertificatePair.
class DoorCertificateWatcher {
public:
	using Apply = std::function<bool(const string &cert_pem, const string &key_pem)>;
	using Report = std::function<void(const DoorCertificateStatus &status, bool failed)>;

	DoorCertificateWatcher(string door, string cert_path, string key_path, idx_t interval_seconds,
	                       const string &served_cert, const string &served_key, Apply apply, Report report);
	~DoorCertificateWatcher();
	DoorCertificateWatcher(const DoorCertificateWatcher &) = delete;
	DoorCertificateWatcher &operator=(const DoorCertificateWatcher &) = delete;

	//! Stop and join (idempotent): the door's stop, its server's teardown, the exit handler.
	void Stop();

private:
	void Run();
	void Check();

	DoorCertificateStatus status;
	string cert_path;
	string key_path;
	idx_t interval_seconds;
	Apply apply;
	Report report;
	//! the files' contents last seen: a pair is checked once per change, a refusal reported once
	string seen_cert;
	string seen_key;
	//! the refusal of what was seen ("" when it is the served pair)
	string seen_refused;
	//! a refused pair waiting for its second look (a renewal read between its two writes)
	string pending_cert;
	string pending_key;

	std::mutex lock;
	std::condition_variable wake;
	bool stopping = false;
	std::thread thread;
};

} // namespace acl
} // namespace duckdb
