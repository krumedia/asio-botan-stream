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
				struct Buffer
				{
					Buffer():
						dynamicBuffer(data_buffer)
					{ }
					std::vector<uint8_t> data_buffer;
					boost::asio::dynamic_vector_buffer<uint8_t, typename decltype(data_buffer)::allocator_type> dynamicBuffer;
				};


				StreamCore()
					: input_buffer_space_(17 * 1024, '\0'), // enough for a TLS Datagram
					input_buffer_(boost::asio::buffer(input_buffer_space_))
				{
				}

				void tls_emit_data(const uint8_t data[], size_t size) override
				{
					auto buffer = send_buffer_.dynamicBuffer.prepare(size);
					auto copySize = boost::asio::buffer_copy(buffer, boost::asio::buffer(data, size));
					send_buffer_.dynamicBuffer.commit(copySize);
				}

				void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
				{
					auto buffer = receive_buffer_.dynamicBuffer.prepare(size);
					auto copySize = boost::asio::buffer_copy(buffer, boost::asio::buffer(data, size));
					receive_buffer_.dynamicBuffer.commit(copySize);
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

				bool hasReceivedData() const
				{
					return receive_buffer_.dynamicBuffer.size() > 0;
				}

				template<typename MutableBufferSequence>
				std::size_t copyReceivedData(MutableBufferSequence buffers)
				{
					auto copiedBytes = boost::asio::buffer_copy(buffers, receive_buffer_.dynamicBuffer.data());
					receive_buffer_.dynamicBuffer.consume(copiedBytes);
					return copiedBytes;
				}

				bool hasDataToSend() const
				{
					return send_buffer_.dynamicBuffer.size() > 0;
				}

				boost::asio::const_buffer sendBuffer() const
				{
					return send_buffer_.dynamicBuffer.data();
				}

				void consumeSendBuffer(std::size_t bytesConsumed)
				{
					send_buffer_.dynamicBuffer.consume(bytesConsumed);
				}

				// Buffer space used to read input intended for the engine.
				std::vector<uint8_t> input_buffer_space_;

				// A buffer that may be used to read input intended for the engine.
				const boost::asio::mutable_buffer input_buffer_;

			private:
				Buffer receive_buffer_;
				Buffer send_buffer_;
			};
		}
	}
}