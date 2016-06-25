/*
The BSD 3-Clause License

Copyright (c) 2016 Egtra All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of {{ project }} nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "stdafx.h"
#include <numeric>
#include <sstream>
#include <unordered_map>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include "EtwCommon.h"

#pragma comment(lib, "tdh.lib")

struct __declspec(uuid("{83ed54f0-4d48-4e45-b16e-726ffd1fa4af}")) Microsoft_Windows_Networking_Correlation;
struct __declspec(uuid("{2ed6006e-4729-4609-b423-3ee7bcd678ef}")) Microsoft_Windows_NDIS_PacketCapture;

/*
per->EventDescriptor.Keyword

0x80000601'40000001 PacketStart
0x80000601'80000001 PacketEnd
0x00000001'00000000 SendPath
0x00000200'00000000 PiiPresent
0x00000400'00000000 Packet
*/

constexpr ULONGLONG KeywordPacketStart = 0x00000000'40000000;
constexpr ULONGLONG KeywordPacketEnd = 0x00000000'80000000;

struct GuidHash
{
	std::size_t operator()(const GUID& x) const noexcept
	{
		union
		{
			std::size_t buffer[sizeof(GUID) / sizeof(std::size_t)];
			GUID guid;
		};
		static_assert(sizeof buffer == sizeof(GUID), "Unknown arch");
		guid = x;
		return std::accumulate(std::begin(buffer), std::end(buffer), std::size_t(), [](auto x, auto y) { return x ^ y; });
	}
};

void CALLBACK EventRecordCallback(_In_ EVENT_RECORD* per)
{
	auto data = static_cast<EventTraceData*>(per->UserContext);

	static std::unordered_map<GUID, std::vector<BYTE>, GuidHash> fragment;
	if (false)
	{
		std::wostringstream s;
		WCHAR tmp[39];
		if (per->EventHeader.ProviderId == __uuidof(Microsoft_Windows_Networking_Correlation))
		{
			s << "C";
		}
		else if (per->EventHeader.ProviderId == __uuidof(Microsoft_Windows_NDIS_PacketCapture))
		{
			s << "P";
		}
		else
		{
			StringFromGUID2(per->EventHeader.ProviderId, tmp, ARRAYSIZE(tmp));
			s << tmp;
		}
		StringFromGUID2(per->EventHeader.ActivityId, tmp, ARRAYSIZE(tmp));
		s << ", Activity ID: " << tmp;
		for (int i = 0; i < per->ExtendedDataCount; ++i)
		{
			const auto& e = per->ExtendedData[i];
			if (e.ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
			{
				const auto& r = *(const EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID*)(e.DataPtr);
				StringFromGUID2(r.RelatedActivityId, tmp, ARRAYSIZE(tmp));
				s << ", RelatedActivityId: " << tmp;
			}
			else
			{
				s << ", ExtType: " << e.ExtType;
			}
		}
		if (per->UserDataLength <= 26 || *((BYTE*)per->UserData + 24) != 0x08 || *((BYTE*)per->UserData + 25) != 0x00)
		{
			if (per->EventHeader.ProviderId == __uuidof(Microsoft_Windows_NDIS_PacketCapture))
			{
				s << " !";
			}
		}
		if (per->EventHeader.ProviderId != __uuidof(Microsoft_Windows_Networking_Correlation))
		{
			ULONG bufferSize = 0;
			auto statusSize = TdhGetEventInformation(per, 0, nullptr, nullptr, &bufferSize);
			if (statusSize != ERROR_INSUFFICIENT_BUFFER)
			{
				return;
			}

			auto buffer = std::make_unique<std::uint8_t[]>(bufferSize);
			auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());
			auto status = TdhGetEventInformation(per, 0, nullptr, info, &bufferSize);
			if (status != ERROR_SUCCESS)
			{
				return;
			}
			for (ULONG i = 0; i < info->TopLevelPropertyCount; i++)
			{
				const auto& propertyInfo = info->EventPropertyInfoArray[i];
				auto name = reinterpret_cast<PCWSTR>(buffer.get() + propertyInfo.NameOffset);
				if (std::wcscmp(name, L"FragmentSize") != 0)
				{
					continue;
				}
				PROPERTY_DATA_DESCRIPTOR desc{
					reinterpret_cast<uintptr_t>(name),
					ULONG_MAX,
				};
				ULONG propertyBufferSize;
				auto statusPropSize = TdhGetPropertySize(per, 0, nullptr, 1, &desc, &propertyBufferSize);
				if (statusPropSize != ERROR_SUCCESS)
				{
					continue;
				}
				auto propertyBuffer = std::make_unique<std::uint8_t[]>(propertyBufferSize);
				auto statusProp = TdhGetProperty(per, 0, nullptr, 1, &desc, propertyBufferSize, propertyBuffer.get());
				if (statusProp != ERROR_SUCCESS)
				{
					continue;
				}
				if ((propertyInfo.Flags & PropertyStruct) != 0)
				{
					continue;
				}
				if (propertyInfo.nonStructType.InType != TDH_INTYPE_UINT32)
				{
					continue;
				}
				s << L", Fragment size: " << *reinterpret_cast<UINT32*>(propertyBuffer.get());
			}

		}
		s << "\r\n";
		OutputDebugStringW(s.str().c_str());
	}

	if (per->EventHeader.ProviderId != __uuidof(Microsoft_Windows_NDIS_PacketCapture))
	{
		return;
	}

	ULONG bufferSize = 0;
	auto statusSize = TdhGetEventInformation(per, 0, nullptr, nullptr, &bufferSize);
	if (statusSize != ERROR_INSUFFICIENT_BUFFER)
	{
		return;
	}

	auto buffer = std::make_unique<std::uint8_t[]>(bufferSize);
	auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());
	auto status = TdhGetEventInformation(per, 0, nullptr, info, &bufferSize);
	if (status != ERROR_SUCCESS)
	{
		return;
	}
	for (ULONG i = 0; i < info->TopLevelPropertyCount; i++)
	{
		const auto& propertyInfo = info->EventPropertyInfoArray[i];
		auto name = reinterpret_cast<PCWSTR>(buffer.get() + propertyInfo.NameOffset);
		if (std::wcscmp(name, L"Fragment") != 0)
		{
			continue;
		}
		PROPERTY_DATA_DESCRIPTOR desc{
			reinterpret_cast<uintptr_t>(name),
			ULONG_MAX,
		};
		ULONG propertyBufferSize;
		auto statusPropSize = TdhGetPropertySize(per, 0, nullptr, 1, &desc, &propertyBufferSize);
		if (statusPropSize != ERROR_SUCCESS)
		{
			continue;
		}
		auto propertyBuffer = std::make_unique<std::uint8_t[]>(propertyBufferSize);
		auto statusProp = TdhGetProperty(per, 0, nullptr, 1, &desc, propertyBufferSize, propertyBuffer.get());
		if (statusProp != ERROR_SUCCESS)
		{
			continue;
		}
		if ((propertyInfo.Flags & PropertyStruct) != 0)
		{
			continue;
		}
		if (propertyInfo.nonStructType.InType != TDH_INTYPE_BINARY)
		{
			continue;
		}

		std::wostringstream s;
		WCHAR tmp[39];
		StringFromGUID2(per->EventHeader.ActivityId, tmp, ARRAYSIZE(tmp));
		s << tmp << ' ' << std::hex << per->EventHeader.Flags;

		auto it = fragment.find(per->EventHeader.ActivityId);
		if (it == fragment.end())
		{
			if ((per->EventHeader.EventDescriptor.Keyword & KeywordPacketEnd) != 0)
			{
				data->Packet.push(std::vector<std::uint8_t>(propertyBuffer.get(), propertyBuffer.get() + propertyBufferSize));
			}
			else
			{
				fragment.emplace(
					per->EventHeader.ActivityId,
					std::vector<std::uint8_t>(propertyBuffer.get(), propertyBuffer.get() + propertyBufferSize));
			}
		}
		else
		{
			it->second.insert(
				it->second.end(),
				propertyBuffer.get(),
				propertyBuffer.get() + propertyBufferSize);
			if ((per->EventHeader.EventDescriptor.Keyword & KeywordPacketEnd) != 0)
			{
				data->Packet.push(std::move(it->second));
				fragment.erase(it);
			}
		}
	}
}
