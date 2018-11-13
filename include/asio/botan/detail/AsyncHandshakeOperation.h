#pragma once
#include <boost/asio/buffer.hpp>
#include <boost/asio.hpp>
#include <botan/tls_channel.h>
#include "StreamCore.h"
#include "AsyncWriteOperation.h"


namespace asio
{
	namespace botan
	{
		namespace detail
		{
			template<typename StreamLayer, typename Handler>
			struct AsyncHandshakeOperation
			{

				AsyncHandshakeOperation(Botan::TLS::Channel& channel, StreamCore& core, StreamLayer& nextLayer, Handler&& handler)
					:channel_(channel),
					core_(core),
					nextLayer_(nextLayer),
					handler_(std::forward<Handler>(handler))
				{ }

				AsyncHandshakeOperation(AsyncHandshakeOperation&& right)
					:channel_(right.channel_),
					core_(right.core_),
					nextLayer_(right.nextLayer_),
					handler_(std::move(right.handler_))
				{ }

				~AsyncHandshakeOperation() = default;
				AsyncHandshakeOperation(AsyncHandshakeOperation&) = delete;

				void operator()(boost::system::error_code ec, std::size_t bytesTransferred = 0, int start = 0)
				{

					// process tls packets from socket first
					if (bytesTransferred > 0)
					{
						auto read_buffer = boost::asio::buffer(core_.input_buffer_, bytesTransferred);
						channel_.received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
					}

					// send tls packets
					if (core_.send_data_.size() > 0)
					{
						AsyncWriteOperation<AsyncHandshakeOperation<StreamLayer, Handler>> op{ core_, std::move(*this), 0 };
						boost::asio::async_write(nextLayer_, core_.send_data_.data(), std::move(op));
						return;
					}

					if (!channel_.is_active() && !ec)
					{
						// we need more tls data from the socket
						nextLayer_.async_read_some(core_.input_buffer_, std::move(*this));
						return;
					}

					if (start)
					{
						// don't call the handler directly, similar to io_context.post
						nextLayer_.async_read_some(boost::asio::buffer(core_.input_buffer_, 0), std::move(*this));
						return;
					}
					handler_(ec);
				}
			private:
				Botan::TLS::Channel& channel_;
				StreamCore& core_;
				StreamLayer& nextLayer_;
				Handler handler_;
			};

		}
	}
}
