#pragma once
#include <boost/asio/buffer.hpp>
#include <boost/asio.hpp>
#include <botan/tls_channel.h>
#include "StreamCore.h"

namespace asio
{
	namespace botan
	{
		namespace detail
		{

			template<typename StreamLayer, typename Handler, typename MutableBufferSequence>
			struct AsyncReadOperation
			{
				AsyncReadOperation(Botan::TLS::Channel& channel, StreamCore& core, StreamLayer& nextLayer, Handler& handler, const MutableBufferSequence& buffers)
					:channel_(channel),
					core_(core),
					nextLayer_(nextLayer),
					handler_(std::move(handler)),
					buffers_(buffers)
				{
				}

				AsyncReadOperation(AsyncReadOperation&& right)
					: channel_(right.channel_),
					core_(right.core_),
					nextLayer_(right.nextLayer_),
					handler_(std::move(right.handler_)),
					buffers_(right.buffers_)
				{
				}

				~AsyncReadOperation() = default;
				AsyncReadOperation(AsyncReadOperation&) = delete;

				void operator()(boost::system::error_code ec,
					std::size_t bytes_transferred = ~std::size_t(0), int start = 0)
				{
					std::size_t decodedBytes = 0;
					{
						std::unique_lock<std::recursive_mutex> lock(core_.receiveMutex_);
						if (bytes_transferred > 0)
						{
							auto read_buffer = boost::asio::buffer(core_.input_buffer_, bytes_transferred);
							channel_.received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
						}
						if (core_.received_data_.size() == 0 && !ec)
						{
							// we need more tls packets from the socket
							nextLayer_.async_read_some(core_.input_buffer_, std::move(*this));
							return;
						}

						if (core_.received_data_.size() > 0)
						{
							if (start == 1)
							{
								// don't call the handler directly, similar to io_context.post
								nextLayer_.async_read_some(boost::asio::buffer(core_.input_buffer_, 0), std::move(*this));
								return;
							}
							decodedBytes = boost::asio::buffer_copy(buffers_, core_.received_data_.data());

							core_.received_data_.consume(decodedBytes);
							ec = boost::system::error_code{};
						}
					}
					handler_(ec, decodedBytes);
				}

			private:

				Botan::TLS::Channel& channel_;
				StreamCore& core_;
				StreamLayer& nextLayer_;
				Handler handler_;
				MutableBufferSequence buffers_;
			};
		}
	}
}

