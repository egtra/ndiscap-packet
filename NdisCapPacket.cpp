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
#include <iphlpapi.h>

#include <evntrace.h>
#include <evntcons.h>

#include "EtwCommon.h"

#pragma comment(lib, "iphlpapi.lib")

using namespace std::literals;

PCHAR PacketGetVersion()
{
	static char version[] = "NdisCapPacket 0.1";
	return version;
}

PCHAR PacketGetDriverVersion()
{
	static char driverVersion[] = "NdisCap";
	return driverVersion;
}

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject, int nbytes)
{
	//assert(false);
	return TRUE;
}

BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject, int nwrites)
{
	assert(false);
	return FALSE;
}

BOOLEAN PacketSetMode(LPADAPTER AdapterObject, int mode)
{
	assert(false);
	return TRUE;
}

BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject, int timeout)
{
	//assert(false);
	return TRUE;
}

BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, bpf_program *fp)
{
	//assert(false);
	return TRUE;
}

BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior)
{
	assert(false);
	return TRUE;
}

INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen)
{
	assert(false);
	return 0;
}

BOOLEAN PacketGetStats(_In_ LPADAPTER AdapterObject, _Out_ bpf_stat* s)
{
	if (s == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	*s = {};
	return TRUE;
}

BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject, bpf_stat *s)
{
	assert(false);
	return FALSE;
}

BOOLEAN PacketSetBuff(LPADAPTER AdapterObject, int dim)
{
	//assert(false);
	return TRUE;
}

BOOLEAN PacketGetNetType(_In_ LPADAPTER AdapterObject, _Out_ NetType* type)
{
	type->LinkType = 0; // NdisMedium802_3
	type->LinkSpeed = 100 * 1000 * 1000;
	return TRUE;
}

LPADAPTER PacketOpenAdapter(_In_ PCHAR AdapterName)
{
	if (AdapterName == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	if (std::strlen(AdapterName) + 1 > sizeof EventTraceData::Name)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}

	try
	{
		auto data = new EventTraceData;
		strcpy_s(data->Name, AdapterName);

		if (!data->ConsumerThread.joinable())
		{

			EVENT_TRACE_LOGFILE etl{};
			etl.LoggerName = const_cast<PWSTR>(SessionName);
			etl.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
			etl.EventRecordCallback = EventRecordCallback;
			etl.Context = data.get();
			auto hTrace = OpenTrace(&etl);
			// See “Return Value” section: https://msdn.microsoft.com/en-us/library/windows/desktop/aa364089(v=vs.85).aspx
#ifdef _WIN64
			ATLENSURE_RETURN_VAL(hTrace != 0xFFFFFFFFFFFFFFFF, nullptr);
#else
			ATLENSURE_RETURN_VAL(hTrace != 0x00000000FFFFFFFF, nullptr);
#endif
			data->TraceHandleConsumer = hTrace;
			data->ConsumerThread = std::thread([hTrace]() mutable
			{
				ProcessTrace(&hTrace, 1, nullptr, nullptr);
			});
		}
		return data.release();
	}
	catch (const std::system_error& e)
	{
		if (e.code().category() == std::system_category())
		{
			SetLastError(static_cast<DWORD>(e.code().value()));
		}
		else
		{
			SetLastError(E_FAIL);
		}
	}
	catch (const std::bad_alloc&)
	{
		SetLastError(ERROR_OUTOFMEMORY);
	}
	catch (...)
	{
		SetLastError(E_FAIL);
	}
	return nullptr;
}

BOOLEAN PacketSendPacket(LPADAPTER AdapterObject, LPPACKET pPacket, BOOLEAN Sync)
{
	assert(false);
	return FALSE;
}

INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync)
{
	assert(false);
	return FALSE;
}

LPPACKET PacketAllocatePacket()
{
	return new(std::nothrow) PACKET{};
}

VOID PacketInitPacket(_Inout_ LPPACKET lpPacket, _In_ PVOID Buffer, _In_ UINT Length)
{
	lpPacket->Buffer = Buffer;
	lpPacket->Length = Length;
	lpPacket->ulBytesReceived = 0;
	lpPacket->bIoComplete = FALSE;
}

VOID PacketFreePacket(_In_opt_ LPPACKET lpPacket)
{
	delete lpPacket;
}

BOOLEAN PacketReceivePacket(_In_ LPADAPTER AdapterObject, _In_ LPPACKET lpPacket, _In_ BOOLEAN Sync)
{
	if (AdapterObject == nullptr || lpPacket == nullptr)
	{
		return FALSE;
	}

	auto data = static_cast<EventTraceData*>(AdapterObject);
	std::vector<std::uint8_t> packet;
	while (!data->Packet.try_pop(packet))
	{
		lpPacket->ulBytesReceived = 0;
		return TRUE;
	}

	auto p = static_cast<std::uint8_t*>(lpPacket->Buffer);
	auto header = reinterpret_cast<bpf_hdr*>(p);
	header->bh_tstamp.tv_sec = time(nullptr);
	header->bh_tstamp.tv_usec = 0;
	header->bh_caplen = packet.size();
	header->bh_datalen = packet.size();
	header->bh_hdrlen = sizeof(bpf_hdr);
	memcpy(p + sizeof(bpf_hdr), packet.data(), packet.size());

	lpPacket->ulBytesReceived = packet.size();

	return TRUE;
}

BOOLEAN PacketSetHwFilter(LPADAPTER AdapterObject, ULONG Filter)
{
	//assert(false);
	return TRUE;
}

BOOLEAN PacketGetAdapterNames(_Out_opt_ PSTR pStr, _Inout_ PULONG BufferSize)
{
	if (BufferSize == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	static constexpr char data[] = "NdisCapPacket\0\0NdisCapPacket\0";
	if (pStr == nullptr || *BufferSize < sizeof data)
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		*BufferSize = sizeof data;
		return FALSE;
	}

	memcpy(pStr, data, sizeof data);
	*BufferSize = sizeof data;
	return TRUE;
}

BOOLEAN PacketGetNetInfoEx(_In_ PCHAR AdapterName, _Out_ npf_if_addr* buffer, _Inout_ PLONG NEntries)
{
	if (AdapterName == nullptr || buffer == nullptr || NEntries == nullptr)
	{
		return FALSE;
	}
	constexpr DWORD Flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
	ULONG addressesBufferSize;
	auto resultSize = GetAdaptersAddresses(AF_UNSPEC, Flags, nullptr, nullptr, &addressesBufferSize);
	if (resultSize != ERROR_BUFFER_OVERFLOW)
	{
		return FALSE;
	}
	std::unique_ptr<std::uint8_t[]> addressesBuffer(new(std::nothrow) std::uint8_t[addressesBufferSize]);
	if (addressesBuffer == nullptr)
	{
		return FALSE;
	}
	auto addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(addressesBuffer.get());
	auto resultAddress = GetAdaptersAddresses(AF_UNSPEC, Flags, nullptr, addresses, &addressesBufferSize);
	if (resultAddress != ERROR_SUCCESS)
	{
		return FALSE;
	}
	ULONG n = *NEntries;
	ULONG i = 0;
	for (; i < n && addresses != nullptr; ++i, addresses = addresses->Next)
	{
		auto a = addresses->FirstUnicastAddress;
		memcpy(&buffer[i].IPAddress, a->Address.lpSockaddr, a->Address.iSockaddrLength);
		buffer[i].SubnetMask = {};
		buffer[i].Broadcast = {};
	}
	*NEntries = i;
	return TRUE;
}

BOOLEAN PacketRequest(LPADAPTER AdapterObject, BOOLEAN Set, PPACKET_OID_DATA OidData)
{
	assert(false);
	return FALSE;
}

HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
	assert(false);
	return nullptr;
}

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
	assert(false);
	return FALSE;
}

BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
	assert(false);
	return FALSE;
}

BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
	assert(false);
	return FALSE;
}

BOOL PacketStopDriver()
{
	assert(false);
	return TRUE;
}

void PacketCloseAdapter(_In_ LPADAPTER lpAdapter)
{
	if (lpAdapter == nullptr)
	{
		return;
	}
	auto data = static_cast<EventTraceData*>(lpAdapter);

	data->ConsumerThread.join();
	CloseTrace(data->TraceHandleConsumer);
	delete data;
}

BOOLEAN PacketStartOem(PCHAR errorString, UINT errorStringLength)
{
	assert(false);
	return FALSE;
}

BOOLEAN PacketStartOemEx(PCHAR errorString, UINT errorStringLength, ULONG flags)
{
	assert(false);
	return FALSE;
}

PAirpcapHandle PacketGetAirPcapHandle(LPADAPTER AdapterObject)
{
	assert(false);
	return nullptr;
}
