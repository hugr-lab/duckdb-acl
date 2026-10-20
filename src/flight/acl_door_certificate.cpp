// Spec 140: a door picks up a renewed certificate - the pair check and the file watcher (the flight
// build's, for its OpenSSL). See acl_door_certificate.hpp.

#include "acl_door_certificate.hpp"

#include "duckdb/common/string_util.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <set>
#include <sstream>

namespace duckdb {
namespace acl {

namespace {

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

bool ReadWhole(const string &path, string &out) {
	std::ifstream in(path, std::ios::binary);
	if (!in) {
		return false;
	}
	std::ostringstream text;
	text << in.rdbuf();
	if (in.bad()) {
		return false;
	}
	out = text.str();
	return true;
}

//! Every watcher alive, for the exit handler: a watcher of a door nobody stopped must not read files or
//! call OpenSSL while the process tears its statics down. Leaked on purpose (spec 084's reasoning).
std::mutex &WatchersLock() {
	static auto *lock = new std::mutex();
	return *lock;
}
std::set<DoorCertificateWatcher *> &Watchers() {
	static auto *watchers = new std::set<DoorCertificateWatcher *>();
	return *watchers;
}
void StopWatchersAtExit() {
	std::set<DoorCertificateWatcher *> all;
	{
		std::lock_guard<std::mutex> guard(WatchersLock());
		all = Watchers();
	}
	for (auto *watcher : all) {
		try {
			watcher->Stop();
		} catch (...) { // NOLINT: nothing may escape an exit handler
		}
	}
}

} // namespace

bool CheckCertificatePair(const string &cert_pem, const string &key_pem, string &not_after, string &error_class) {
	auto *cert_bio = BIO_new_mem_buf(cert_pem.data(), NumericCast<int>(cert_pem.size()));
	X509 *cert = cert_bio ? PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr) : nullptr;
	if (cert_bio) {
		BIO_free(cert_bio);
	}
	if (!cert) {
		error_class = "certificate_unparsable";
		return false;
	}
	auto *key_bio = BIO_new_mem_buf(key_pem.data(), NumericCast<int>(key_pem.size()));
	EVP_PKEY *key = key_bio ? PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr) : nullptr;
	if (key_bio) {
		BIO_free(key_bio);
	}
	if (!key) {
		X509_free(cert);
		error_class = "key_unparsable";
		return false;
	}
	// httplib's update sets the certificate, then the key: a key of another certificate would leave the
	// door holding a pair that matches nothing - so a pair is judged whole, before anything takes it
	auto matches = X509_check_private_key(cert, key) == 1;
	struct tm when {};
	auto have_time = ASN1_TIME_to_tm(X509_get0_notAfter(cert), &when) == 1;
	EVP_PKEY_free(key);
	X509_free(cert);
	if (!matches) {
		error_class = "key_mismatch";
		return false;
	}
	not_after.clear();
	if (have_time) {
		char text[32];
		if (strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &when) > 0) {
			not_after = text;
		}
	}
	error_class.clear();
	return true;
}

DoorCertificateWatcher::DoorCertificateWatcher(string door, string cert_path_p, string key_path_p,
                                               idx_t interval_seconds_p, const string &served_cert,
                                               const string &served_key, Apply apply_p, Report report_p)
    : cert_path(std::move(cert_path_p)), key_path(std::move(key_path_p)), interval_seconds(interval_seconds_p),
      apply(std::move(apply_p)), report(std::move(report_p)), seen_cert(served_cert), seen_key(served_key) {
	status.door = std::move(door);
	status.watched = true;
	status.refreshed_at = NowSeconds();
	string error_class;
	CheckCertificatePair(served_cert, served_key, status.not_after, error_class);
	if (report) {
		report(status, false);
	}
	{
		static std::once_flag once;
		std::call_once(once, [] { std::atexit(StopWatchersAtExit); });
		std::lock_guard<std::mutex> guard(WatchersLock());
		Watchers().insert(this);
	}
	thread = std::thread([this]() { Run(); });
}

DoorCertificateWatcher::~DoorCertificateWatcher() {
	try {
		Stop();
	} catch (...) { // NOLINT: a destructor throws nothing
	}
}

void DoorCertificateWatcher::Stop() {
	{
		std::lock_guard<std::mutex> guard(lock);
		stopping = true;
	}
	wake.notify_all();
	if (thread.joinable() && thread.get_id() != std::this_thread::get_id()) {
		thread.join();
	}
	std::lock_guard<std::mutex> guard(WatchersLock());
	Watchers().erase(this);
}

void DoorCertificateWatcher::Run() {
	while (true) {
		{
			std::unique_lock<std::mutex> guard(lock);
			wake.wait_for(guard, std::chrono::seconds(interval_seconds), [this]() { return stopping; });
			if (stopping) {
				return;
			}
		}
		Check();
	}
}

void DoorCertificateWatcher::Check() {
	string cert, key;
	if (!ReadWhole(cert_path, cert) || !ReadWhole(key_path, key)) {
		if (status.error != "unreadable") {
			status.error = "unreadable";
			if (report) {
				report(status, true);
			}
		}
		return;
	}
	if (cert == seen_cert && key == seen_key) {
		// nothing new: the served pair, or a refusal already reported - files readable again after a
		// failed read hold what was seen, so that refusal is over
		if (status.error == "unreadable") {
			status.error = seen_refused;
			if (report) {
				report(status, false);
			}
		}
		return;
	}
	string not_after, error_class;
	auto good = CheckCertificatePair(cert, key, not_after, error_class);
	if (!good && (cert != pending_cert || key != pending_key)) {
		// a renewal is two files: read between the two writes, a certificate meets the old key. The same
		// content is judged once more at the next check before it is called broken - the csi-driver swaps
		// both at once, and a pair still refused an interval later is one
		pending_cert = cert;
		pending_key = key;
		return;
	}
	pending_cert.clear();
	pending_key.clear();
	seen_cert = cert;
	seen_key = key;
	if (good && apply && !apply(cert, key)) {
		good = false;
		error_class = "refused_by_door";
	}
	if (!good) {
		status.error = seen_refused = error_class;
		if (report) {
			report(status, true);
		}
		return;
	}
	seen_refused.clear();
	status.not_after = not_after;
	status.refreshed_at = NowSeconds();
	status.error.clear();
	if (report) {
		report(status, false);
	}
}

} // namespace acl
} // namespace duckdb
