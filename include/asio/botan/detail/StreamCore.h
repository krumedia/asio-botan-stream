#pragma once
#include <vector>
#include <mutex>
#include <boost/asio/buffer.hpp>
#include <botan/tls_callbacks.h>

namespace asio
{
	namespace botan
	{
		namespace detail
		{
			/**
			* Contains the buffers for reading/sending, and the needed botan callbacks
			*/
			struct StreamCore : public Botan::TLS::Callbacks
			{
				StreamCore()
					: input_buffer_space_(17 * 1024, '\0'), // enough for a TLS Datagram
					input_buffer_(boost::asio::buffer(input_buffer_space_)),
					received_data_(received_data_buffer_),
					send_data_(send_data_buffer_)
				{
				}


				void tls_emit_data(const uint8_t data[], size_t size) override
				{
					std::unique_lock<std::recursive_mutex> lock(sendMutex_);
					auto buffer = send_data_.prepare(size);
					auto copySize = boost::asio::buffer_copy(buffer, boost::asio::buffer(data, size));
					send_data_.commit(copySize);
				}

				void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
				{
					std::unique_lock<std::recursive_mutex> lock(receiveMutex_);
					auto buffer = received_data_.prepare(size);
					auto copySize = boost::asio::buffer_copy(buffer, boost::asio::buffer(data, size));
					received_data_.commit(copySize);
				}

				void tls_alert(Botan::TLS::Alert alert) override
				{
					if (alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
					{

					}
				}

				bool tls_session_established(const Botan::TLS::Session& session) override
				{
					return true;
				}


				std::recursive_mutex receiveMutex_;
				std::recursive_mutex sendMutex_;

				// Buffer space used to read input intended for the engine.
				std::vector<unsigned char> input_buffer_space_;

				// A buffer that may be used to read input intended for the engine.
				const boost::asio::mutable_buffer input_buffer_;

				std::vector<uint8_t> received_data_buffer_;
				boost::asio::dynamic_vector_buffer<uint8_t, typename decltype(received_data_buffer_)::allocator_type> received_data_;


				std::vector<uint8_t> send_data_buffer_;
				boost::asio::dynamic_vector_buffer<uint8_t, typename decltype(send_data_buffer_)::allocator_type> send_data_;
			};
		}
	}
}