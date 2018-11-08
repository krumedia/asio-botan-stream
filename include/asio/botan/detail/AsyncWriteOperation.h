#pragma once
#include <boost/asio/buffer.hpp>
#include "StreamCore.h"
#include <boost/asio.hpp>

namespace asio
{
	namespace botan
	{
		namespace detail
		{

			template<typename Handler>
			struct AsyncWriteOperation
			{
				AsyncWriteOperation(StreamCore& core, Handler& handler, std::size_t plainBytesTransferred)
					: core_(core),
					handler_(std::move(handler)),
					plainBytesTransferred_(plainBytesTransferred)
				{
				}

				AsyncWriteOperation(AsyncWriteOperation&& right)
					:core_(right.core_),
					handler_(std::move(right.handler_)),
					plainBytesTransferred_(right.plainBytesTransferred_)
				{
				}

				~AsyncWriteOperation() = default;
				AsyncWriteOperation(AsyncWriteOperation&) = delete;

				void operator()(boost::system::error_code ec, std::size_t bytes_transferred = ~std::size_t(0))
				{
					{
						std::unique_lock<std::recursive_mutex> lock(core_.sendMutex_);
						core_.send_data_.consume(bytes_transferred);
					}
					handler_(ec, plainBytesTransferred_);
				}

				StreamCore& core_;
				Handler handler_;
				std::size_t plainBytesTransferred_;
			};
		}
	}
}