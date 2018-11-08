#include <asio/botan/Stream.h>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <botan/hash.h>
#include <gtest/gtest.h>
#include <memory>

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}



namespace
{
#ifdef WIN32
	static const char* CA_DIR = "c:\\certs\\";
#else
	static const char* CA_DIR = "/etc/ssl/certs/";
#endif

	using namespace Botan;
	class CertificateStore : public Botan::Certificate_Store
	{
	public:
		CertificateStore() = default;


		void add_certificate(const X509_Certificate& cert)
		{
		}

		void add_certificate(std::shared_ptr<const X509_Certificate> cert)
		{
		}

		std::vector<X509_DN> all_subjects() const
		{
			std::vector<X509_DN> subjects;
			return subjects;
		}

		std::shared_ptr<const X509_Certificate>
			find_cert(const X509_DN& subject_dn,
				const std::vector<uint8_t>& key_id) const
		{

			return nullptr;
		}

		std::shared_ptr<const X509_Certificate> find_cert_by_name(std::string name,
			const X509_DN& subject_dn,
			const std::vector<uint8_t>& key_id) const
		{
			std::replace(name.begin(), name.end(), ' ', '_');
			auto fileName = std::string(CA_DIR) + name + ".pem";
			if (boost::filesystem::exists(fileName))
			{
				auto cert = std::make_shared<const X509_Certificate>(fileName);
				// Only compare key ids if set in both call and in the cert
				if (key_id.size())
				{
					std::vector<uint8_t> skid = cert->subject_key_id();

					if (skid.size() && skid != key_id) // no match
						return {};
				}

				if (cert->subject_dn() == subject_dn)
					return{ cert };
			}
			return {};
		}

		std::vector<std::shared_ptr<const X509_Certificate>> find_all_certs(
			const X509_DN& subject_dn,
			const std::vector<uint8_t>& key_id) const
		{
			auto cn = subject_dn.get_first_attribute("X520.CommonName");
			auto cert = find_cert_by_name(subject_dn.get_first_attribute("X520.CommonName"), subject_dn, key_id);
			if (cert) return { cert };
			cert = find_cert_by_name(subject_dn.get_first_attribute("X520.Organization"), subject_dn, key_id);
			if (cert) return { cert };
			cert = find_cert_by_name(subject_dn.get_first_attribute("X520.OrganizationalUnit"), subject_dn, key_id);
			if (cert) return { cert };
			std::vector<std::shared_ptr<const X509_Certificate>> matches;
			return matches;
		}

		std::shared_ptr<const X509_Certificate>
			find_cert_by_pubkey_sha1(const std::vector<uint8_t>& key_hash) const
		{
			if (key_hash.size() != 20)
				throw Invalid_Argument("Certificate_Store_In_Memory::find_cert_by_pubkey_sha1 invalid hash");

			std::unique_ptr<Botan::HashFunction> hash(HashFunction::create("SHA-1"));

			return nullptr;
		}

		std::shared_ptr<const X509_Certificate>
			find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const
		{
			if (subject_hash.size() != 32)
				throw Invalid_Argument("Certificate_Store_In_Memory::find_cert_by_raw_subject_dn_sha256 invalid hash");

			std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
			return nullptr;
		}

		void add_crl(const Botan::X509_CRL& crl)
		{
			std::shared_ptr<const Botan::X509_CRL > crl_s = std::make_shared<const Botan::X509_CRL>(crl);
			return add_crl(crl_s);
		}

		void add_crl(std::shared_ptr<const Botan::X509_CRL> crl)
		{
			X509_DN crl_issuer = crl->issuer_dn();
		}

		std::shared_ptr<const Botan::X509_CRL> find_crl_for(const X509_Certificate& subject) const
		{
			const std::vector<uint8_t>& key_id = subject.authority_key_id();
			return {};
		}


	};

	class CredentialsManager : public Botan::Credentials_Manager
	{
	public:
		CredentialsManager()
		{
		}
		std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
			const std::string& type,
			const std::string& context) override
		{
			static CertificateStore _certificateStore{};
			return{ &_certificateStore };
		}

	private:
	};


	class Policy : public Botan::TLS::Default_Policy
	{
	public:
		Policy() = default;

		bool require_cert_revocation_info() const override
		{
			return false;
		}
	};
}


TEST(AsioBotan, testWithBeast)
{
	Botan::TLS::Session_Manager_Noop sessionManager;
	CredentialsManager credentialManager;
	Policy policy;

	boost::asio::io_context io;
	boost::asio::ip::tcp::resolver resolver(io);
	auto endpoints = resolver.resolve("www.google.com", "https");


	boost::asio::ip::tcp::socket socket{ io };
	boost::asio::connect(socket, endpoints);

	asio::botan::ClientStream<boost::asio::ip::tcp::socket&> ssl{ socket, sessionManager, credentialManager, policy };


	boost::system::error_code ec;
	ssl.handshake(ec);

	namespace http = boost::beast::http;

	// Set up an HTTP GET request message
	http::request<http::string_body> req{ http::verb::get, "/", 11 };
	req.set(http::field::host, "www.google.com");
	req.set(http::field::user_agent, "test");

	// Send the HTTP request to the remote host
	http::write(ssl, req);

	// This buffer is used for reading and must be persisted
	boost::beast::flat_buffer buffer;

	// Declare a container to hold the response
	http::response<http::dynamic_body> res;

	// Receive the HTTP response
	http::read(ssl, buffer, res);

	// Write the message to standard out
	std::cout << res << std::endl;

	// Gracefully close the socket
	boost::system::error_code ec2;
	ssl.shutdown(ec2);
	socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec2);
	std::cout << ec2.message();
}



namespace
{
	using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
	namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


	// Report a failure
	void
		fail(boost::system::error_code ec, char const* what)
	{
		std::cerr << what << ": " << ec.message() << "\n";
	}

	// Performs an HTTP GET and prints the response
	class session : public std::enable_shared_from_this<session>
	{
		Botan::TLS::Session_Manager_Noop sessionManager;
		CredentialsManager credentialManager;
		Policy policy;


		tcp::resolver resolver_;
		tcp::socket socket_;
		asio::botan::ClientStream<boost::asio::ip::tcp::socket&> ssl;
		boost::beast::flat_buffer buffer_; // (Must persist between reads)
		http::request<http::empty_body> req_;
		http::response<http::string_body> res_;

	public:
		// Resolver and socket require an io_context
		explicit
			session(boost::asio::io_context& ioc)
			: resolver_(ioc)
			, socket_(ioc),
			ssl(socket_, sessionManager, credentialManager, policy)
		{
		}
		~session()
		{
			std::cout << "dctr" << std::endl;
		}

		// Start the asynchronous operation
		void
			run(
				char const* host,
				char const* port,
				char const* target,
				int version)
		{
			// Set up an HTTP GET request message
			req_.version(version);
			req_.method(http::verb::get);
			req_.target(target);
			req_.set(http::field::host, host);
			req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

			// Look up the domain name
			resolver_.async_resolve(
				host,
				port,
				std::bind(
					&session::on_resolve,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2));
		}

		void
			on_resolve(
				boost::system::error_code ec,
				tcp::resolver::results_type results)
		{
			if (ec)
				return fail(ec, "resolve");

			// Make the connection on the IP address we get from a lookup
			boost::asio::async_connect(
				socket_,
				results.begin(),
				results.end(),
				std::bind(
					&session::on_connect,
					shared_from_this(),
					std::placeholders::_1));
		}


		void
			on_connect(boost::system::error_code ec)
		{
			if (ec)
				return fail(ec, "connect");

			// Perform the SSL handshake
			ssl.async_handshake(
				std::bind(
					&session::on_handshake,
					shared_from_this(),
					std::placeholders::_1));
		}

		void
			on_handshake(boost::system::error_code ec)
		{
			if (ec)
				return fail(ec, "handshake");

			// Send the HTTP request to the remote host
			http::async_write(ssl, req_,
				std::bind(
					&session::on_write,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2));
		}

		void
			on_write(
				boost::system::error_code ec,
				std::size_t bytes_transferred)
		{
			boost::ignore_unused(bytes_transferred);

			if (ec)
				return fail(ec, "write");

			// Receive the HTTP response
			http::async_read(ssl, buffer_, res_,
				std::bind(
					&session::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2));
		}

		void
			on_read(
				boost::system::error_code ec,
				std::size_t bytes_transferred)
		{
			boost::ignore_unused(bytes_transferred);

			if (ec)
				return fail(ec, "read");

			// Write the message to standard out
			std::cout << res_ << std::endl;

			ssl.shutdown(ec);

			// Gracefully close the socket
			socket_.shutdown(tcp::socket::shutdown_both, ec);

			// not_connected happens sometimes so don't bother reporting it.
			if (ec && ec != boost::system::errc::not_connected)
				return fail(ec, "shutdown");

			// If we get here then the connection is closed gracefully
		}
	};

}

TEST(AsioBotan, testWithBeastAsync)
{

	auto const host = "www.google.com";
	auto const port = "https";
	auto const target = "/";
	int version = 11;

	// The io_context is required for all I/O
	boost::asio::io_context ioc;

	// Launch the asynchronous operation
	std::make_shared<session>(ioc)->run(host, port, target, version);

	// Run the I/O service. The call will return when
	// the get operation is complete.
	ioc.run();
}