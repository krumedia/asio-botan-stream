#pragma once
#include <boost/asio/buffer.hpp>
#include <boost/asio.hpp>
#include <botan/tls_channel.h>
#include "StreamCore.h"
#include "ConvertExceptions.h"

namespace asio
{
	namespace botan
	{
		namespace detail
		{

			template<typename StreamLayer, typename Handler, typename MutableBufferSequence>
			struct AsyncReadOperation
			{
				AsyncReadOperation(Botan::TLS::Channel& channel, StreamCore& core, StreamLayer& nextLayer, Handler&& handler, const MutableBufferSequence& buffers)
					:channel_(channel),
					core_(core),
					nextLayer_(nextLayer),
					handler_(std::forward<Handler>(handler)),
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
						if (bytes_transferred > 0)
						{
							auto read_buffer = boost::asio::buffer(core_.input_buffer_, bytes_transferred);
							try
							{
								channel_.received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
							}
							catch (...)
							{
								ec = detail::convertException();
								handler_(ec, 0);
								return;
							}
						}
						if (!core_.hasReceivedData() && !ec)
						{
							// we need more tls packets from the socket
							nextLayer_.async_read_some(core_.input_buffer_, std::move(*this));
							return;
						}

						if (core_.hasReceivedData())
						{
							if (start == 1)
							{
								// don't call the handler directly, similar to io_context.post
								nextLayer_.async_read_some(boost::asio::buffer(core_.input_buffer_, 0), std::move(*this));
								return;
							}
							decodedBytes = core_.copyReceivedData(buffers_);
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

